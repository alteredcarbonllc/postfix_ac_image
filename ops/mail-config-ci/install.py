#!/usr/bin/python3
"""Install CI importer and runtime interlock without restarting mail."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile

# Use the installed, already running implementation during the upgrade.
sys.path.insert(0,'/usr/local/libexec/ac-mail-switch')
import mail_runtime as r
sys.path.insert(0,str(Path(__file__).resolve().parent))
import mail_config as c

HERE=Path(__file__).resolve().parent
LIB=Path('/usr/local/libexec/ac-mail-config')

def mkdir(path,mode=0o755):
    c.safe_parents(path)
    if path.exists() or path.is_symlink(): c.safe(path,True)
    else: path.mkdir(mode=mode)

def install():
    c.need(os.geteuid()==0,'Run as root');os.umask(0o077)
    account=pwd.getpwnam('ac-ci-builder');c.need(account.pw_uid==1001,'Unexpected builder UID')
    with r.locks():
        c.need(not r.PENDING.exists() and not c.PENDING.exists(),'Pending mail transaction')
        runtime=Path('/usr/local/libexec/ac-mail-switch/mail_runtime.py')
        hashes=json.loads((HERE/'runtime-sha256.json').read_text())
        previous=runtime.read_bytes();updated=(HERE/'mail_runtime.py').read_bytes()
        c.need(c.sha(previous) in (hashes['before'],hashes['after']) and c.sha(updated)==hashes['after'],'Unexpected runtime version')
        c.need((HERE/'mail_release.py').read_bytes()==Path('/usr/local/libexec/ac-mail-switch/mail_release.py').read_bytes(),'Unexpected release helper')
        destinations={LIB/'mail_config.py':(HERE/'mail_config.py',0o644),Path('/usr/local/sbin/ac-mail-config'):(HERE/'ac-mail-config',0o755)}
        for target,(source,mode) in destinations.items():
            c.safe_parents(target) if target.parent.exists() else None
            if target.exists() or target.is_symlink():
                c.safe(target);c.need(target.read_bytes()==source.read_bytes(),'Existing tool differs: '+str(target))
        r.healthy_pair(c.check_active());c.adopt()
        mkdir(Path('/var/spool/ac-mail'))
        mkdir(c.INBOX)
        for kind in r.SERVICES:
            path=c.INBOX/kind
            if path.exists() or path.is_symlink():
                st=path.lstat();c.need(not path.is_symlink() and path.is_dir() and st.st_uid==account.pw_uid and st.st_mode&0o777==0o700,'Unexpected inbox mode/owner')
            else:
                path.mkdir(mode=0o700);os.chown(path,account.pw_uid,account.pw_gid)
        queue=Path('/var/spool/ac-mail/config-ci.lock')
        if not queue.exists():
            fd=os.open(queue,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd);os.chown(queue,account.pw_uid,account.pw_gid)
        else:
            st=queue.lstat();c.need(not queue.is_symlink() and queue.is_file() and st.st_uid==account.pw_uid and st.st_mode&0o777==0o600,'Unexpected CI lock')
        mkdir(LIB)
        rules=''.join('ac-ci-builder ALL=(root) NOPASSWD: /usr/local/sbin/ac-mail-config '+action+' '+kind+' *\n' for kind in r.SERVICES for action in ('prepare','apply'))
        sudoers=Path('/etc/sudoers.d/ac-mail-config')
        if sudoers.exists(): c.safe(sudoers);c.need(sudoers.read_text()==rules,'Existing sudoers differs')
        backup=Path(tempfile.mkdtemp(prefix='config-tool-upgrade-',dir=r.STATE))
        r.atomic(backup/'mail_runtime.py',previous)
        r.atomic(backup/'sudoers.new',rules.encode(),0o440)
        r.run(['/usr/sbin/visudo','-cf',str(backup/'sudoers.new')])
        for target,(source,mode) in destinations.items():r.atomic(target,source.read_bytes(),mode)
        r.atomic(runtime,updated,0o644)
        r.atomic(sudoers,rules.encode(),0o440)
        r.run(['/usr/sbin/visudo','-c'])
        print('MAIL_CONFIG_CI_INSTALLED: no restart; backup='+str(backup))
        print('CI_DEPLOY_ENABLED='+str(c.ENABLED.exists()).lower())

if __name__=='__main__':
    try: install()
    except Exception as e:
        print('INSTALL_ERROR: '+(str(e) if isinstance(e,RuntimeError) else type(e).__name__),file=sys.stderr)
        sys.exit(1)
