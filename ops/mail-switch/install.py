#!/usr/bin/python3
"""Install inactive mail supervisors. No running container is modified."""
import os
from pathlib import Path
import stat
import sys
import mail_runtime as r

HERE=Path(__file__).resolve().parent

def protected(path):
    for parent in (path,*path.parents):
        if not parent.exists() and not parent.is_symlink(): continue
        st=parent.lstat()
        r.require(not stat.S_ISLNK(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,
                  'Unsafe installation path: '+str(parent))

def install():
    r.require(os.geteuid()==0,'Run as root');os.umask(0o077)
    protected(r.STATE);r.STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with r.locks():
        r.require(not r.ACTIVE.exists() and not r.PENDING.exists() and not r.MARKER.exists(),
                  'Mail already managed or a migration is pending')
        r.verify_reference(HERE)
        targets={}
        for filename in ('mail_runtime.py','mail_release.py','reference-sha256.json'):
            targets[r.LIB/filename]=(HERE/filename,0o644)
        for source in (HERE/'legacy').iterdir(): targets[r.LIB/'legacy'/source.name]=(source,0o644)
        targets[Path('/usr/local/sbin/ac-mailctl')]=(HERE/'ac-mailctl',0o755)
        for s in r.SERVICES:
            r.require(r.run(['systemctl','is-active','--quiet',r.unit(s)],check=False).returncode!=0,'Supervisor already running')
            r.require(r.run(['systemctl','is-enabled','--quiet',r.unit(s)],check=False).returncode!=0,'Supervisor already enabled')
            targets[Path('/etc/systemd/system')/r.unit(s)]=(HERE/r.unit(s),0o644)
            for part in ('run','finish','control/t','log/run'):
                targets[r.service_dir(s)/part]=(HERE/'runit'/s/part,0o755)
        # Inspect every destination before writing any file; no implicit tool upgrades.
        for target,(source,mode) in targets.items():
            protected(target)
            r.require(not target.exists() or target.read_bytes()==source.read_bytes(),
                      'Existing file differs: '+str(target))
        for s in r.SERVICES:
            directory=r.service_dir(s);protected(directory)
            directory.mkdir(mode=0o755,parents=True,exist_ok=True)
            r.atomic(directory/'down',b'')
            logs=Path('/var/log/ac-'+s+'-supervisor');protected(logs)
            logs.mkdir(mode=0o700,parents=True,exist_ok=True)
            config=logs/'config'
            if not config.exists(): r.atomic(config,b's1000000\nn10\n')
        for target,(source,mode) in targets.items(): r.atomic(target,source.read_bytes(),mode)
        r.run(['systemctl','daemon-reload'])
    print('MAIL_SWITCH_TOOLS_INSTALLED_DOWN: no container changes; no supervisor started')

if __name__=='__main__':
    try: install()
    except Exception as e:
        print('INSTALL_ERROR: '+(str(e) if type(e) is RuntimeError else type(e).__name__),file=sys.stderr)
        sys.exit(1)
