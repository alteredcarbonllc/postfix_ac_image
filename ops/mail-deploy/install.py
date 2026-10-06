#!/usr/bin/python3
"""Install release preparer only. No services, container changes or sudoers grants."""
import ast
import os
from pathlib import Path
import tempfile

root = Path(__file__).resolve().parent
library = Path('/usr/local/libexec/ac-mail')
wrapper = Path('/usr/local/sbin/ac-mail-release')
source = (root/'mail_release.py').read_bytes()
ast.parse(source)
script = b'#!/bin/sh\nexec /usr/bin/python3 /usr/local/libexec/ac-mail/mail_release.py "$@"\n'

def install():
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    os.umask(0o077)
    targets = [(library/'mail_release.py', source, 0o644), (wrapper, script, 0o755)]
    for path, data, mode in targets:
        if path.is_symlink() or (path.exists() and path.read_bytes() != data):
            raise SystemExit('STOP: existing different tool: '+str(path))
    library.mkdir(mode=0o755, parents=True, exist_ok=True)
    for path, data, mode in targets:
        if path.exists():
            os.chmod(path, mode)
            continue
        fd, tmp = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as f:
                os.fchmod(f.fileno(), mode)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
    print('MAIL_RELEASE_TOOL_INSTALLED: no services or containers changed')

if __name__ == '__main__': install()
