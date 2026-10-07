#!/usr/bin/python3
"""Install import-only privilege; no production runtime changes."""
import ast
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile

SERVICE = 'postfix'
def safe_dir(path):
    for p in [*reversed(path.parents),path]:
        st=p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise RuntimeError('Unsafe directory: '+str(p))
def directory(path,mode):
    safe_dir(path.parent)
    if path.exists() or path.is_symlink(): safe_dir(path)
    else: path.mkdir(mode=mode)
    path.chmod(mode)
def write(path,data,mode):
    safe_dir(path.parent)
    if path.exists() or path.is_symlink():
        st=path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise RuntimeError('Unsafe destination')
        if path.read_bytes()!=data:
            raise RuntimeError('Existing importer differs; explicit upgrade required')
    fd,tmp=tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),mode)
            f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
def main():
    if os.geteuid()!=0: raise RuntimeError('Run as root')
    os.umask(0o077)
    account=pwd.getpwnam('ac-ci-builder')
    if account.pw_uid!=1001: raise RuntimeError('Expected builder UID 1001')
    data=Path(__file__).with_name('ac-'+SERVICE+'-import').read_bytes()
    ast.parse(data)
    subprocess.run(['/usr/sbin/visudo','-c'],check=True)
    root=Path('/var/spool/ac-mail-images')
    directory(root,0o755)
    directory(root/SERVICE,0o755)
    inbox=root/SERVICE/'inbox'
    if inbox.exists() or inbox.is_symlink():
        st=inbox.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=1001 or stat.S_IMODE(st.st_mode)!=0o700:
            raise RuntimeError('Unexpected inbox')
    else:
        inbox.mkdir(mode=0o700);os.chown(inbox,1001,account.pw_gid)
    state=Path('/var/lib/ac-mail')
    if state.exists(): safe_dir(state)
    else: directory(state,0o700)
    directory(state/'image-imports',0o700)
    directory(state/'image-imports'/SERVICE,0o700)
    wrapper=Path('/usr/local/sbin/ac-'+SERVICE+'-import')
    rules=('ac-ci-builder ALL=(root) NOPASSWD: '+str(wrapper)+' *\n').encode()
    with tempfile.TemporaryDirectory(prefix='install-import-',dir=state) as tmp:
        check=Path(tmp)/'sudoers'
        check.write_bytes(rules);check.chmod(0o440)
        subprocess.run(['/usr/sbin/visudo','-cf',str(check)],check=True)
        write(wrapper,data,0o755)
        write(Path('/etc/sudoers.d/ac-'+SERVICE+'-import'),rules,0o440)
    subprocess.run(['/usr/sbin/visudo','-c'],check=True)
    print('MAIL_IMAGE_IMPORT_INSTALLED: '+SERVICE+'; production unchanged')
if __name__=='__main__': main()
