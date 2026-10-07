"""Disposable SQL fixture; optionally starts a Dovecot peer for Postfix tests."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

BIN = '/usr/lib/postgresql/16/bin/'
stop = False
def terminate(*_):
    global stop
    stop = True
for sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, terminate)

def run(args, **kw):
    return subprocess.run(args, check=True, **kw)
def pg(*args, **kw):
    return run(['/usr/sbin/runuser', '-u', 'postgres', '--', *args], **kw)

Path('/tmp/ci').mkdir(mode=0o755)
run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
     '-subj','/CN=ci.invalid','-addext','subjectAltName=DNS:ci.invalid,IP:127.0.0.1',
     '-keyout','/tmp/ci/key.pem','-out','/tmp/ci/cert.pem'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
pg(BIN+'initdb','-D','/tmp/ci-pg','--auth-local=trust','--auth-host=trust','--locale=C.UTF-8')
database = subprocess.Popen(['/usr/sbin/runuser','-u','postgres','--',BIN+'postgres','-D','/tmp/ci-pg','-k','/tmp','-c','listen_addresses=127.0.0.1'])
dovecot = None
try:
    for _ in range(60):
        if subprocess.run([BIN+'pg_isready','-h','127.0.0.1'],stdout=subprocess.DEVNULL).returncode == 0:
            break
        if stop or database.poll() is not None:
            raise RuntimeError('Fixture database exited')
        time.sleep(0.5)
    else:
        raise RuntimeError('Fixture database timeout')
    pg(BIN+'psql','-h','/tmp','-X','-v','ON_ERROR_STOP=1','-d','postgres','-c',
       "CREATE ROLE mail LOGIN PASSWORD 'ci-db-only';")
    pg(BIN+'createdb','-h','/tmp','-O','mail','mail')
    pg(BIN+'psql','-h','/tmp','-X','-v','ON_ERROR_STOP=1','-d','mail','-c',
       """CREATE TABLE users(userid text PRIMARY KEY, password text NOT NULL, active char(1));
INSERT INTO users VALUES ('probe@ci.invalid','{PLAIN}ci-test-only','Y');
GRANT SELECT ON users TO mail;""")
    if len(sys.argv) > 1 and sys.argv[1] == 'postfix':
        shutil.copyfile('/fixture/dovecot.conf','/etc/dovecot/dovecot.conf')
        shutil.copyfile('/fixture/dovecot-sql.conf','/etc/dovecot/ci-sql.conf')
        Path('/var/log/dovecot').mkdir(parents=True,exist_ok=True)
        Path('/var/mail').mkdir(exist_ok=True)
        os.chown('/var/mail',55004,55004)
        os.chmod('/var/mail',0o700)
        dovecot = subprocess.Popen(['dovecot','-F'])
        for _ in range(40):
            p = subprocess.run(['doveadm','user','probe@ci.invalid'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if p.returncode == 0:
                break
            if dovecot.poll() is not None: raise RuntimeError('Fixture Dovecot exited')
            time.sleep(0.5)
        else: raise RuntimeError('Fixture Dovecot not ready')
    Path('/tmp/ci/ready').touch()
    while not stop:
        if database.poll() is not None or (dovecot is not None and dovecot.poll() is not None):
            raise RuntimeError('Fixture child exited')
        time.sleep(0.2)
finally:
    if dovecot is not None and dovecot.poll() is None:
        dovecot.terminate()
        dovecot.wait(timeout=60)
    if database.poll() is None:
        pg(BIN+'pg_ctl','-D','/tmp/ci-pg','-m','fast','-w','-t','90','stop')
        database.wait(timeout=15)
