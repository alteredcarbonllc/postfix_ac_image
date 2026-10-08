#!/usr/bin/python3
"""Install reviewed updater and config-CI compatibility; no service restart."""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

SOURCE=Path(__file__).resolve().parent
sys.path.insert(0,'/usr/local/libexec/ac-mail-switch')
sys.path.insert(0,'/usr/local/libexec/ac-mail-config')
import mail_runtime as r
import mail_config as c

DEST={
    'mail_runtime.py':Path('/usr/local/libexec/ac-mail-switch/mail_runtime.py'),
    'mail_release.py':Path('/usr/local/libexec/ac-mail-switch/mail_release.py'),
    'mail_config.py':Path('/usr/local/libexec/ac-mail-config/mail_config.py'),
    'mail_image.py':Path('/usr/local/libexec/ac-mail-image/mail_image.py'),
    'ac-mail-image':Path('/usr/local/sbin/ac-mail-image'),
}

def install():
    r.require(os.geteuid()==0,'Run as root');os.umask(0o077)
    for name in DEST:
        path=SOURCE/name
        r.require(path.is_file() and not path.is_symlink(),'Invalid installer source')
        if name.endswith('.py'): ast.parse(path.read_text())
    reference=json.loads((SOURCE/'engine-sha256.json').read_text())
    with r.locks():
        r.require(not r.PENDING.exists() and not (r.STATE/'pending-image.json').exists(),'Pending mail transaction')
        active=c.check_active()
        for entry in r.readjson(c.CURRENT).values(): c.check_files(entry)
        r.healthy_pair(active)
        for name,target in DEST.items():
            for parent in target.parents:
                if parent==DEST['mail_image.py'].parent and not parent.exists(): continue
                c.safe(parent,True)
            if target.exists() or target.is_symlink():
                c.safe(target)
                digest=hashlib.sha256(target.read_bytes()).hexdigest()
                expected=hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()
                r.require(digest in (reference.get(str(target)),expected),'Installed source differs: '+str(target))
            else:
                r.require(name in ('mail_image.py','ac-mail-image'),'Missing existing deployment engine')
        report=Path(tempfile.mkdtemp(prefix='image-tool-upgrade-',dir=r.STATE))
        directory=DEST['mail_image.py'].parent
        if not directory.exists(): directory.mkdir(mode=0o755);directory.chmod(0o755)
        c.safe(directory,True)
        before={}
        for name,target in DEST.items():
            if target.exists():
                before[name]=(target.read_bytes(),target.stat().st_mode&0o777)
                r.atomic(report/name,before[name][0])
            else: before[name]=None
        try:
            for name,target in DEST.items():
                r.atomic(target,(SOURCE/name).read_bytes(),0o755 if name=='ac-mail-image' else 0o644)
        except BaseException:
            for name,target in reversed(list(DEST.items())):
                if before[name] is None: target.unlink(missing_ok=True)
                else: r.atomic(target,*before[name])
            raise
        r.putjson(report/'installed-sha256.json',{
            str(target):hashlib.sha256(target.read_bytes()).hexdigest() for target in DEST.values()})
        print('MAIL_IMAGE_TOOLS_INSTALLED: no restart; backup='+str(report))
        print('CONFIG_CI_ENABLED='+str(c.ENABLED.exists()).lower())

if __name__=='__main__':
    try: install()
    except Exception as error:
        print('INSTALL_ERROR: '+str(error),file=sys.stderr);sys.exit(1)
