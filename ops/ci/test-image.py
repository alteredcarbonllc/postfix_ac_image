#!/usr/bin/python3
"""Candidate tests without production mounts, network, credentials or mail."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

SERVICE = 'postfix'
POD = ['/usr/local/bin/podman','--remote=false']
HERE = Path(__file__).resolve().parent
def need(ok, message):
    if not ok: raise RuntimeError(message)
def pod(*args, **kwargs):
    return subprocess.run(POD+list(args),check=kwargs.pop('check',True),text=True,capture_output=True,timeout=kwargs.pop('timeout',180),**kwargs)
def metadata(image,revision):
    cfg=image['Config']
    need(image.get('Os')=='linux' and image.get('Architecture')=='amd64','Wrong platform')
    need(cfg.get('User')=='root' and not cfg.get('Entrypoint'),'Wrong user/entrypoint')
    need(cfg.get('Cmd')==(['dovecot','-F'] if SERVICE=='dovecot' else ['postfix','start-fg']),'Wrong CMD')
    need(cfg.get('StopSignal') in ('SIGTERM','15',15),'Wrong stop signal')
    need(not cfg.get('Volumes'),'Anonymous volumes refused')
    labels=image.get('Labels') or cfg.get('Labels') or {}
    need(labels.get('org.opencontainers.image.revision')==revision,'Wrong revision')
def write(cid,path,data,mode='600'):
    pod('exec','-i',cid,'sh','-ec','cat > "$1"; chmod "$2" "$1"','sh',path,mode,input=data)
def main():
    image,fixture,revision=sys.argv[1:]
    need(re.fullmatch('[0-9a-f]{40}',revision),'Invalid revision')
    need(os.getuid()==1001,'Expected builder UID 1001')
    need(pod('info','--format','{{.Host.Security.Rootless}}').stdout.strip()=='true','Rootless storage required')
    meta=json.loads(pod('image','inspect',image).stdout)[0]
    metadata(meta,revision)
    image=meta['Id']
    fixture=json.loads(pod('image','inspect',fixture).stdout)[0]['Id']
    report=Path(tempfile.mkdtemp(prefix='ac-'+SERVICE+'-ci-'))
    print('TEST_REPORT='+str(report),flush=True)
    ids=[]
    succeeded=False
    try:
        fx=pod('create','--name','ac-'+SERVICE+'-fixture-'+uuid.uuid4().hex[:12],
               '--pull=never','--network=none','--restart=no',fixture,
               'python3','/fixture/server.py',SERVICE).stdout.strip()
        ids.append(fx)
        pod('start',fx)
        for _ in range(90):
            if pod('exec',fx,'test','-f','/tmp/ci/ready',check=False).returncode==0: break
            need(json.loads(pod('inspect',fx).stdout)[0]['State']['Running'],'Fixture exited')
            time.sleep(0.5)
        else: raise RuntimeError('Fixture startup timeout')
        command='dovecot -F' if SERVICE=='dovecot' else 'postfix start-fg'
        cid=pod('create','--name','ac-'+SERVICE+'-check-'+uuid.uuid4().hex[:12],
                '--pull=never','--network=container:'+fx,'--restart=no',
                '--entrypoint=/bin/sh',image,'-ec',
                'while [ ! -f /tmp/ci/go ]; do sleep 0.2; done; exec '+command).stdout.strip()
        ids.append(cid)
        pod('start',cid)
        info=json.loads(pod('inspect',cid).stdout)[0]
        need(not info.get('Mounts'),'Test candidate unexpectedly has mounts')
        pod('exec',cid,'mkdir','-p','/tmp/ci','/var/log/'+SERVICE)
        for name in ('cert.pem','key.pem'):
            write(cid,'/tmp/ci/'+name,pod('exec',fx,'cat','/tmp/ci/'+name).stdout,'644' if name=='cert.pem' else '600')
        expected={'vmail':(55004,55004)}
        expected.update({'dovecot':(100,102),'dovenull':(101,103)} if SERVICE=='dovecot' else {'postfix':(100,102)})
        for account,(uid,gid) in expected.items():
            need(pod('exec',cid,'id','-u',account).stdout.strip()==str(uid),'UID changed: '+account)
            need(pod('exec',cid,'id','-g',account).stdout.strip()==str(gid),'GID changed: '+account)
        if SERVICE=='dovecot':
            version=pod('exec',cid,'dovecot','--version').stdout.strip()
            need(version.startswith('2.3.'),'Dovecot major/minor upgrade requires review')
            schemes=pod('exec',cid,'doveadm','pw','-l').stdout.split()
            need({'ARGON2I','ARGON2ID','CRYPT'}<=set(schemes),'Password schemes missing')
            # Authenticate SQL against a freshly generated ARGON2I verifier.
            password_hash=pod('exec',cid,'doveadm','pw','-s','ARGON2I','-p','ci-test-only').stdout.strip()
            need(password_hash.startswith('{ARGON2I}') and "'" not in password_hash,'Invalid ARGON2I output')
            pod('exec',fx,'/usr/sbin/runuser','-u','postgres','--','/usr/lib/postgresql/16/bin/psql',
                '-h','/tmp','-X','-v','ON_ERROR_STOP=1','-d','mail','-c',
                "UPDATE users SET password='"+password_hash+"' WHERE userid='probe@ci.invalid';")
            write(cid,'/etc/dovecot/dovecot.conf',(HERE/'fixtures/dovecot.conf').read_text(),'644')
            write(cid,'/etc/dovecot/ci-sql.conf',(HERE/'fixtures/dovecot-sql.conf').read_text())
            pod('exec',cid,'doveconf','-n')
        else:
            version=pod('exec',cid,'postconf','-h','mail_version').stdout.strip()
            need(version.startswith('3.8.'),'Postfix major/minor upgrade requires review')
            need('pgsql' in pod('exec',cid,'postconf','-m').stdout.split(),'pgsql driver missing')
            need('dovecot' in pod('exec',cid,'postconf','-a').stdout.split(),'Dovecot SASL missing')
            need(pod('exec',cid,'getent','group','postdrop').stdout.split(':')[2]=='103','postdrop GID changed')
            pod('exec',cid,'mkdir','-p','/etc/postfix/pgsql')
            for name in ('main.cf','master.cf'):
                write(cid,'/etc/postfix/'+name,(HERE/'fixtures'/name).read_text(),'644')
            queries={
                'virtual_mailbox_domains': "SELECT DISTINCT split_part(userid,'@',2) FROM users WHERE split_part(userid,'@',2)='%s' AND active='Y'",
                'virtual_mailbox_maps': "SELECT userid FROM users WHERE userid='%s' AND active='Y'",
                'sender_login_maps': "SELECT userid FROM users WHERE userid='%s' AND active='Y'",
                'recipient_bbc_maps': "SELECT userid FROM users WHERE false",
            }
            for name,query in queries.items():
                path='/etc/postfix/pgsql/'+name+'.pgsql'
                write(cid,path,'hosts = 127.0.0.1\nuser = mail\npassword = ci-db-only\ndbname = mail\nquery = '+query+'\n','640')
                pod('exec',cid,'chown','root:postfix',path)
            for key,expected_result in [('ci.invalid','ci.invalid'),('unknown.invalid','')]:
                lookup = pod(
                    'exec', cid, 'postmap', '-q', key,
                    'pgsql:/etc/postfix/pgsql/virtual_mailbox_domains.pgsql',
                    check=False,
                )
                expected_code = 0 if expected_result else 1
                need(
                    lookup.returncode == expected_code
                    and lookup.stdout.strip() == expected_result
                    and not lookup.stderr.strip(),
                    'SQL domain lookup failed: key=' + key
                    + ' exit=' + str(lookup.returncode)
                    + ' stderr=' + lookup.stderr.strip(),
                )
            pod('exec',cid,'postfix','check')
            expected_paths = {
                '/var/lib/postfix': '100:102 755',
                '/var/spool/postfix': '0:0 755',
                '/var/spool/postfix/active': '100:0 700',
                '/var/spool/postfix/deferred': '100:0 700',
                '/var/spool/postfix/maildrop': '100:103 1730',
                '/var/spool/postfix/public': '100:103 2710',
                '/var/spool/postfix/private': '100:0 700',
            }
            for path, mode in expected_paths.items():
                need(pod('exec',cid,'stat','-c','%u:%g %a',path).stdout.strip()==mode,
                     'Queue/data ownership or mode differs: '+path)
        (report/'version.txt').write_text(version+'\n')
        pod('exec',cid,'touch','/tmp/ci/go')
        for _ in range(60):
            probe=pod('exec',fx,'python3','-c',
                      "import socket; s=socket.create_connection(('127.0.0.1',"+('993' if SERVICE=='dovecot' else '587')+"),1); s.close()",check=False)
            if probe.returncode==0: break
            need(json.loads(pod('inspect',cid).stdout)[0]['State']['Running'],'Candidate exited')
            time.sleep(0.5)
        else: raise RuntimeError('Candidate listener timeout')
        result=pod('exec',fx,'python3','/fixture/probe.py',SERVICE,timeout=180,check=False)
        (report/'probe.txt').write_text(result.stdout)
        (report/'probe.stderr').write_text(result.stderr)
        print(result.stdout,end='',flush=True)
        print(result.stderr,end='',file=sys.stderr,flush=True)
        result.check_returncode()
        if SERVICE=='postfix':
            for _ in range(30):
                if not pod('exec',cid,'postqueue','-j').stdout.strip(): break
                time.sleep(0.5)
            else: raise RuntimeError('Test queue not empty')
        succeeded=True
    finally:
        clean=True
        for cid in reversed(ids):
            try:
                if json.loads(pod('inspect',cid).stdout)[0]['State']['Running']:
                    pod('kill','--signal=TERM',cid)
                for _ in range(120):
                    state=json.loads(pod('inspect',cid).stdout)[0]['State']
                    if not state['Running']: break
                    time.sleep(0.5)
                # Daemons may use files instead of stdout; keep synthetic test logs.
                pod('cp',cid+':/var/log/'+SERVICE,str(report/(cid[:12]+'-service-log')),check=False)
                logs=pod('logs',cid,check=False)
                (report/(cid[:12]+'.log')).write_text(logs.stdout+logs.stderr)
                if state['Running'] or state['ExitCode']!=0 or state.get('OOMKilled'):
                    clean=False
                (report/(cid[:12]+'.json')).write_text(json.dumps(state,indent=2))
            except Exception as exc:
                clean=False
                (report/(cid[:12]+'.cleanup-error')).write_text(str(exc))
        if succeeded and clean:
            for cid in reversed(ids): pod('rm',cid)
        else:
            print('TEST_CONTAINERS_RETAINED: '+' '.join(ids),flush=True)
        need(clean,'Test shutdown not clean; inspect report')
    print('MAIL_IMAGE_TEST_OK: '+SERVICE+' '+revision,flush=True)

if __name__=='__main__':
    main()
