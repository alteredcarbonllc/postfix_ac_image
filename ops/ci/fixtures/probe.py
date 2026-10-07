"""Runs INSIDE the network-none fixture; only artificial test messages."""
from email.message import EmailMessage
import imaplib
import poplib
import smtplib
import ssl
import sys
import time
import uuid

kind = sys.argv[1]
user, password = 'probe@ci.invalid', 'ci-test-only'
context = ssl.create_default_context(cafile='/tmp/ci/cert.pem')
message = EmailMessage()
message['From'] = user
message['To'] = user
message['Subject'] = 'Isolated CI delivery'
message['Message-ID'] = '<ci-' + uuid.uuid4().hex + '@ci.invalid>'
message.set_content('Synthetic message in disposable test storage.')

def need(ok, why):
    if not ok: raise RuntimeError(why)

if kind == 'dovecot':
    with smtplib.LMTP('127.0.0.1',24,timeout=15) as client:
        need(not client.send_message(message), 'LMTP rejected test message')
    print('LMTP_ACCEPTED')
else:
    with smtplib.SMTP('127.0.0.1',25,timeout=15) as client:
        client.ehlo()
        need(not client.has_extn('auth') and client.has_extn('starttls'),'SMTP25 capabilities')
        client.starttls(context=context)
        client.ehlo()
        need(not client.has_extn('auth'),'SMTP25 AUTH exposed after TLS')
        for recipient, allowed in [(user,True),('absent@ci.invalid',False),('probe@example.invalid',False)]:
            client.rset()
            need(client.mail('')[0]==250, 'MAIL failed')
            code, _ = client.rcpt(recipient)
            need(code==250 if allowed else 500<=code<600, 'Recipient/relay restriction failed')
        client.rset()
    print('SMTP25_RECIPIENT_AND_RELAY_OK')
    for port in (587,465):
        with (smtplib.SMTP_SSL('127.0.0.1',port,context=context,timeout=15) if port==465
              else smtplib.SMTP('127.0.0.1',port,timeout=15)) as client:
            client.ehlo()
            if port==587:
                client.starttls(context=context)
                client.ehlo()
            client.login(user,password)
            code,_=client.mail('other@ci.invalid')
            if code==250: code,_=client.rcpt(user)
            need(500<=code<600,'Sender mismatch was not rejected')
            client.rset()
            if port==587:
                need(not client.send_message(message),'Submission failed')
        print('SUBMISSION_TLS_AUTH_AND_SENDER_OK:',port)
# Wait for queue delivery and observe the exact Message-ID via IMAP.
for attempt in range(40):
    with imaplib.IMAP4_SSL('127.0.0.1',993,ssl_context=context,timeout=15) as client:
        client.login(user,password)
        need(client.select('INBOX',readonly=True)[0]=='OK','INBOX open failed')
        status, data=client.search(None,'HEADER','Message-ID',message['Message-ID'])
        if status=='OK' and data and data[0].strip(): break
    time.sleep(0.5)
else: raise RuntimeError('Message not found through IMAP')
client = poplib.POP3_SSL('127.0.0.1',995,context=context,timeout=15)
try:
    client.user(user)
    client.pass_(password)
    need(client.stat()[0]>=1,'POP3 message absent')
    client.quit()
finally:
    client.close()
print('TLS_IMAP_POP3_AND_DELIVERY_OK')
