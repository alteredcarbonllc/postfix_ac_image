#!/usr/bin/python3
"""Prepare and validate mail configuration releases; never activate production."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

STATE = Path('/var/lib/ac-mail')
POD = '/usr/local/bin/podman'
CERTS = Path('/var/volumes/data/letsencrypt_container_openmailserver.net/etc/letsencrypt')
ENV = {'HOME': '/root', 'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
NAMES = ('virtual_mailbox_domains', 'virtual_mailbox_maps', 'sender_login_maps', 'recipient_bbc_maps')
SPEC = {
 'dovecot': {'revision': '78d852e2f61d5769aaf5ccb8115d2775f43e6524',
             'image': '912bf1ecec596b61f0cdf916e1b9ed2cb7391f9e7c90f925d3ae1850b041b769',
             'files': ['dovecot/dovecot.conf', 'templates/dovecot-sql.conf.ext.in']},
 'postfix': {'revision': 'df0940e',
             'image': '99fccf28180e9990e6ea17831bac96c5ecd145397829f621723929abf43a5bf6',
             'files': ['postfix/main.cf', 'postfix/master.cf'] + ['templates/pgsql/'+n+'.pgsql.in' for n in NAMES]},
}

class Failure(Exception):
    pass

def require(ok, message):
    if not ok:
        raise Failure(message)

def command(argv, timeout=120):
    # Never include command output in exceptions: configuration errors may contain secrets.
    r = subprocess.run(argv, cwd='/', env=ENV, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    require(r.returncode == 0, 'Command failed: '+Path(argv[0]).name)
    return r.stdout

def git(repo, *args):
    return command(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(repo), *args])

def digest(data):
    return hashlib.sha256(data).hexdigest()

def snapshot(repo, kind):
    repo = Path(repo).resolve(strict=True)
    require(not git(repo, 'status', '--porcelain', '--untracked-files=all'), 'Repository is not clean: '+kind)
    revision = git(repo, 'rev-parse', '--verify', 'HEAD^{commit}').decode().strip()
    approved = git(repo, 'rev-parse', '--verify', SPEC[kind]['revision']+'^{commit}').decode().strip()
    require(re.fullmatch('[0-9a-f]{40}', revision) and revision == approved, 'Unapproved HEAD: '+kind)
    result = {}
    for name in SPEC[kind]['files']:
        listing = git(repo, 'ls-tree', '-z', revision, '--', name).split(b'\0')
        require(len(listing) == 2 and not listing[1], 'Missing source: '+name)
        meta, actual = listing[0].split(b'\t', 1)
        mode, typ, oid = meta.split()
        require(mode == b'100644' and typ == b'blob' and actual.decode() == name, 'Unsafe source type: '+name)
        data = git(repo, 'cat-file', 'blob', oid.decode())
        require(len(data) <= 262144 and b'\0' not in data, 'Invalid source size/content')
        data.decode('utf-8')
        result[name] = data
    return revision, result

def read_secret(path):
    path = Path(path)
    for parent in path.parents:
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'Unsafe secret parent: '+str(parent))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o600,
                'Secret must be root-owned mode 0600')
        data = stream.read(65537)
    require(len(data) <= 65536, 'Secret is too large')
    return json.loads(data)

def scalar(value):
    require(isinstance(value, str) and value and not any(c in value for c in '\r\n\x00'),
            'Invalid secret value')
    return value

def substitute(template, values):
    text = template.decode()
    markers = re.findall(r'@[A-Z_]+@', text)
    require(sorted(markers) == sorted('@'+k+'@' for k in values), 'Unexpected template markers')
    for value in values.values():
        scalar(value)
    # One pass: marker-like strings in credentials remain literal.
    return re.sub(r'@([A-Z_]+)@', lambda m: values[m[1]], text).encode()

def render(kind, files, secret):
    if kind == 'dovecot':
        return {'config/dovecot.conf': files['dovecot/dovecot.conf'],
                'secrets/dovecot-sql.conf.ext': substitute(files['templates/dovecot-sql.conf.ext.in'],
                                                         {'SQL_CONNECT': secret['connect']})}
    output = {'config/main.cf': files['postfix/main.cf'], 'config/master.cf': files['postfix/master.cf']}
    keys = {'SQL_HOSTS': 'hosts', 'SQL_DATABASE': 'dbname', 'SQL_USER': 'user', 'SQL_PASSWORD': 'password'}
    for name in NAMES:
        values = secret['maps'][name]
        output['secrets/'+name+'.pgsql'] = substitute(files['templates/pgsql/'+name+'.pgsql.in'],
                                                     {k: values[v] for k, v in keys.items()})
    return output

def save(path, data, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as f:
        os.fchmod(f.fileno(), mode)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def manifest_for(kind, revision, source, rendered):
    return {'format': 1, 'service': kind, 'revision': revision, 'image': SPEC[kind]['image'],
            'source_sha256': {k: digest(v) for k, v in source.items()},
            'rendered_sha256': {k: digest(v) for k, v in rendered.items()}}

def check_tree(root, expected):
    actual = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory)/name
            s = path.lstat()
            require(not stat.S_ISLNK(s.st_mode), 'Symlink in release')
            if stat.S_ISREG(s.st_mode):
                rel = path.relative_to(root).as_posix()
                actual.add(rel)
                require(rel in expected and digest(path.read_bytes()) == expected[rel], 'Release drift: '+rel)
            else:
                require(stat.S_ISDIR(s.st_mode), 'Special file in release')
    require(actual == set(expected), 'Missing release files')

def validate(kind, root):
    image = SPEC[kind]['image']
    command([POD, '--remote=false', 'image', 'exists', image])
    base = [POD, '--remote=false', 'run', '--rm', '--pull=never', '--network=none', '--user=0:0']
    def mount(src, dst):
        require(',' not in str(src), 'Unsupported path')
        base.extend(['--mount', 'type=bind,source='+str(src)+',destination='+dst+',ro=true'])
    mount(CERTS, '/etc/letsencrypt')
    if kind == 'dovecot':
        mount(root/'config', '/etc/dovecot')
        mount(root/'secrets', '/run/secrets/dovecot')
        args = ['--entrypoint=/usr/bin/doveconf', image, '-c', '/etc/dovecot/dovecot.conf', '-n']
    else:
        mount(root/'config', '/candidate')
        mount(root/'secrets', '/candidate-maps')
        args = ['--entrypoint=/bin/sh', image, '-ec', '''
cp /candidate/main.cf /etc/postfix/main.cf
cp /candidate/master.cf /etc/postfix/master.cf
chmod 0644 /etc/postfix/main.cf /etc/postfix/master.cf
mkdir -p /etc/postfix/pgsql /var/log/postfix
cp /candidate-maps/*.pgsql /etc/postfix/pgsql/
chown root:postfix /etc/postfix/pgsql /etc/postfix/pgsql/*.pgsql
chmod 0750 /etc/postfix/pgsql
chmod 0640 /etc/postfix/pgsql/*.pgsql
postconf -e 'inet_interfaces = loopback-only'
postfix check
postconf -M >/dev/null
''']
    # Private logs; not echoed even on failure.
    try:
        r = subprocess.run(base+args, cwd='/', env=ENV, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=90)
    except subprocess.TimeoutExpired:
        raise Failure('Validation timeout; inspect Podman for retained validation container')
    save(root/'validation.stdout', r.stdout)
    save(root/'validation.stderr', r.stderr)
    require(r.returncode == 0, 'Validation failed; see private validation.stderr')

def prepare(kind, repo, secret_path):
    revision, source = snapshot(repo, kind)
    rendered = render(kind, source, read_secret(secret_path))
    manifest = manifest_for(kind, revision, source, rendered)
    # Hash includes rendered secret hashes: a changed secret yields a new immutable release.
    encoded = (json.dumps(manifest, sort_keys=True, indent=2)+'\n').encode()
    release_id = revision+'-'+digest(encoded)[:16]
    parent = STATE/'releases'/kind
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    dest = parent/release_id
    if dest.exists() or dest.is_symlink():
        verify_release(dest, kind)
        require((dest/'manifest.json').read_bytes() == encoded, 'Existing release differs')
        print('RELEASE_EXISTS: '+str(dest))
        return dest
    staging = Path(tempfile.mkdtemp(prefix='.prepare-', dir=parent))
    try:
        for name, data in rendered.items():
            save(staging/name, data)
        save(staging/'manifest.json', encoded)
        validate(kind, staging)
        save(staging/'VALIDATED', b'Parse check only; production unchanged.\n')
        os.rename(staging, dest)
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    except BaseException:
        print('PRIVATE_FAILED_REPORT: '+str(staging), file=sys.stderr)
        raise
    print('RELEASE_PREPARED: '+str(dest))
    return dest

def verify_release(root, kind):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), 'Invalid release directory')
    for directory, dirs, files in os.walk(root, followlinks=False):
        for path in [Path(directory)] + [Path(directory)/n for n in dirs+files]:
            s = path.lstat()
            require(s.st_uid == 0 and not s.st_mode & 0o077, 'Release must remain private and root-owned')
    raw = (root/'manifest.json').read_bytes()
    manifest = json.loads(raw)
    revision = manifest.get('revision', '')
    require(re.fullmatch('[0-9a-f]{40}', revision) is not None, 'Invalid revision')
    require(root.name == revision+'-'+digest(raw)[:16], 'Manifest or release name changed')
    require(revision.startswith(SPEC[kind]['revision']), 'Unapproved release revision')
    required = ({'config/dovecot.conf', 'secrets/dovecot-sql.conf.ext'} if kind == 'dovecot' else
                {'config/main.cf', 'config/master.cf'} | {'secrets/'+n+'.pgsql' for n in NAMES})
    require(set(manifest['rendered_sha256']) == required, 'Unexpected rendered file list')
    require(set(manifest['source_sha256']) == set(SPEC[kind]['files']), 'Unexpected source file list')
    require(manifest['format'] == 1 and manifest['service'] == kind and
            manifest['image'] == SPEC[kind]['image'], 'Unexpected manifest')
    extra = ['manifest.json', 'validation.stdout', 'validation.stderr', 'VALIDATED']
    expected = dict(manifest['rendered_sha256'])
    expected.update({k: digest((root/k).read_bytes()) for k in extra})
    check_tree(root, expected)
    require((root/'VALIDATED').read_bytes() == b'Parse check only; production unchanged.\n', 'Unvalidated release')
    return manifest

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['prepare', 'verify'])
    p.add_argument('service', choices=list(SPEC))
    p.add_argument('path', help='Git working tree for prepare; release path for verify')
    args = p.parse_args()
    require(os.geteuid() == 0, 'Run as root')
    os.umask(0o077)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = STATE.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o077, 'Unsafe state directory')
    with (STATE/'release.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == 'prepare':
            prepare(args.service, args.path, '/etc/ac/secrets/'+args.service+'/sql.json')
        else:
            verify_release(Path(args.path), args.service)
            print('RELEASE_INTEGRITY_OK')
    print('PRODUCTION_UNCHANGED')

if __name__ == '__main__':
    try: main()
    except (Exception, KeyboardInterrupt) as e:
        # Avoid secret-bearing messages from JSON/parser/subprocess exceptions.
        print('MAIL_RELEASE_ERROR: '+(str(e) if isinstance(e, Failure) else type(e).__name__), file=sys.stderr)
        sys.exit(1)
