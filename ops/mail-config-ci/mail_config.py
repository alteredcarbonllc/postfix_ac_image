#!/usr/bin/python3
"""Private mail configuration import and transactional activation."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import sys
import tarfile
import tempfile

sys.path.insert(0,'/usr/local/libexec/ac-mail-switch')
import mail_runtime as r

STATE=r.STATE
INBOX=Path('/var/spool/ac-mail/config-inbox')
RELEASES=STATE/'ci-releases'
CURRENT=STATE/'active-config.json'
PENDING=STATE/'pending-config.json'
ENABLED=STATE/'config-ci-enabled'
LIMIT=4*1024*1024
UID=1001

def need(ok,message): r.require(ok,message)
def sha(data): return hashlib.sha256(data).hexdigest()
def safe(path,directory=False):
    st=path.lstat()
    need((stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)) and st.st_uid==0 and not st.st_mode&0o022,'Unsafe root-owned path: '+str(path))
    return st

def safe_parents(path):
    for parent in path.parents: safe(parent,True)

def decode_archive(path,kind):
    allowed=set(r.releases.SPEC[kind]['files']);files={};seen=set()
    dirs={str(p) for f in allowed for p in PurePosixPath(f).parents if str(p)!='.'}
    with tarfile.open(path,'r:') as archive:
        members=archive.getmembers()
        need(len(members)<=32,'Too many archive entries')
        for m in members:
            name=m.name.rstrip('/') if m.isdir() else m.name
            need(name not in seen and not name.startswith('/') and '..' not in PurePosixPath(name).parts and str(PurePosixPath(name))==name,'Unsafe or duplicate archive path')
            seen.add(name)
            if m.isdir(): need(name in dirs,'Unknown archive directory');continue
            need(m.isfile() and name in allowed and m.size<=262144 and m.mode&0o111==0,'Unexpected archive member')
            with archive.extractfile(m) as stream: data=stream.read(262145)
            need(len(data)==m.size and b'\x00' not in data,'Invalid file content')
            data.decode('utf-8');files[name]=data
    need(set(files)==allowed,'Missing configuration files')
    return files

def snapshot_inbox(kind,revision,target):
    directory=INBOX/kind;safe_parents(directory)
    dirfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        ds=os.fstat(dirfd);need(ds.st_uid==UID and stat.S_IMODE(ds.st_mode)==0o700,'Unsafe inbox')
        fd=os.open(revision+'.tar',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=dirfd)
        with os.fdopen(fd,'rb') as source,target.open('xb') as out:
            st=os.fstat(source.fileno())
            need(stat.S_ISREG(st.st_mode) and st.st_uid==UID and 0<st.st_size<=LIMIT,'Invalid inbox archive')
            total=0
            while True:
                block=source.read(65536)
                if not block: break
                total+=len(block);need(total<=LIMIT,'Archive too large');out.write(block)
            end=os.fstat(source.fileno())
            need(total==st.st_size and (st.st_mtime_ns,st.st_ctime_ns,st.st_size)==(end.st_mtime_ns,end.st_ctime_ns,end.st_size),'Archive changed during import')
            out.flush();os.fsync(out.fileno())
    finally: os.close(dirfd)

def prepare(kind,revision):
    parent=RELEASES/kind;parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    stage=Path(tempfile.mkdtemp(prefix='.prepare-',dir=parent))
    print('PRIVATE_IMPORT_REPORT='+str(stage),flush=True)
    snapshot_inbox(kind,revision,stage/'source.tar')
    files=decode_archive(stage/'source.tar',kind)
    secret=r.releases.read_secret(Path('/etc/ac/secrets')/kind/'sql.json')
    rendered=r.releases.render(kind,files,secret)
    manifest={'format':1,'service':kind,'revision':revision,'image':r.releases.SPEC[kind]['image'],
              'source':{k:sha(v) for k,v in files.items()},'rendered':{k:sha(v) for k,v in rendered.items()}}
    raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    # A revision cannot later name different submitted source, even after a secret rotation.
    receipt=STATE/'ci-source-receipts'/kind/(revision+'.json')
    if receipt.exists(): need(r.readjson(receipt)==manifest['source'],'Same revision has different source')
    target=parent/(revision+'-'+sha(raw)[:16])
    if target.exists():
        verify_release(target,kind);shutil.rmtree(stage);return target
    for filename,data in rendered.items(): r.atomic(stage/filename,data)
    r.atomic(stage/'manifest.json',raw)
    r.releases.validate(kind,stage)
    r.atomic(stage/'VALIDATED',b'CONFIG_PARSE_OK\n')
    (stage/'source.tar').unlink()
    r.putjson(receipt,manifest['source'])
    os.rename(stage,target)
    print('MAIL_CONFIG_PREPARED: '+kind+' '+revision,flush=True)
    return target

def verify_release(path,kind):
    need(path.parent==RELEASES/kind and not path.is_symlink(),'Invalid CI release path');safe_parents(path)
    safe(path,True);raw=(path/'manifest.json').read_bytes();m=json.loads(raw)
    need(m['format']==1 and m['service']==kind and m['image']==r.releases.SPEC[kind]['image'],'Invalid release manifest')
    need(re.fullmatch('[0-9a-f]{40}',m['revision']) and path.name==m['revision']+'-'+sha(raw)[:16],'Release identity differs')
    expected=set(['config/dovecot.conf','secrets/dovecot-sql.conf.ext']) if kind=='dovecot' else {'config/main.cf','config/master.cf'}|{'secrets/'+n+'.pgsql' for n in r.releases.NAMES}
    need(set(m['rendered'])==expected,'Unexpected release files')
    need(set(m['source'])==set(r.releases.SPEC[kind]['files']),'Unexpected source list')
    actual=set()
    for p in path.rglob('*'):
        st=safe(p,p.is_dir());need(not st.st_mode&0o077,'Release is not private')
        if p.is_file(): actual.add(str(p.relative_to(path)))
    need(actual==expected|{'manifest.json','VALIDATED','validation.stdout','validation.stderr'},'Unexpected release tree')
    for filename,digest in m['rendered'].items(): need(sha((path/filename).read_bytes())==digest,'Release content drift')
    need((path/'VALIDATED').read_bytes()==b'CONFIG_PARSE_OK\n','Release not validated')
    return m

def targets(kind,c):
    mounts={m['Destination']:Path(m['Source']) for m in c['Mounts']}
    base=mounts['/etc/'+kind]
    result={'config/'+n:base/n for n in (('dovecot.conf',) if kind=='dovecot' else ('main.cf','master.cf'))}
    if kind=='dovecot': result['secrets/dovecot-sql.conf.ext']=mounts['/run/secrets/dovecot']/'dovecot-sql.conf.ext'
    else: result.update({'secrets/'+n+'.pgsql':base/'pgsql'/(n+'.pgsql') for n in r.releases.NAMES})
    for p in result.values():
        need(p.is_relative_to(STATE) and p.resolve()==p,'Working file outside mail state');safe_parents(p);safe(p)
    return result

def file_record(path):
    st=safe(path)
    return {'path':str(path),'sha256':sha(path.read_bytes()),'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode)}

def check_files(entry):
    for metadata in entry['files'].values(): need(file_record(Path(metadata['path']))==metadata,'Working configuration drift: '+metadata['path'])

def check_active(require_running=True):
    need(not r.PENDING.exists(),'Pending initial mail migration')
    active=r.readjson(r.ACTIVE)
    for kind in r.SERVICES:
        c=r.inspect(active[kind]['id']);r.verify_active(kind,c)
        if require_running:
            need(c['State']['Running'] and not (r.service_dir(kind)/'down').exists(),'Service deliberately stopped or not running')
        need(c['Image'].removeprefix('sha256:')==r.releases.SPEC[kind]['image'],'Image deployment requires a separate review')
    return active

def adopt():
    active=check_active();state={}
    if CURRENT.exists():
        state=r.readjson(CURRENT)
        for kind in r.SERVICES: check_files(state[kind])
        return
    for kind in r.SERVICES:
        release=Path(active[kind]['release']);r.releases.verify_release(release,kind)
        mapping=targets(kind,r.inspect(active[kind]['id']))
        for filename,dest in mapping.items(): need(dest.read_bytes()==(release/filename).read_bytes(),'Bootstrap configuration differs from release')
        state[kind]={'release':str(release),'revision':r.readjson(release/'manifest.json')['revision'],
                     'files':{filename:file_record(dest) for filename,dest in mapping.items()}}
    r.putjson(CURRENT,state)

def stopped(active):
    for kind in reversed(r.SERVICES):
        r.verify_active(kind,r.inspect(active[kind]['id']))
        r.pause(kind);r.stop_id(active[kind]['id'])
    for kind in r.SERVICES: need(not r.inspect(active[kind]['id'])['State']['Running'],'Mail pair still running')

def started(active):
    for kind in r.SERVICES:
        r.up(kind);r.wait_health(kind,active[kind]['id']);r.verify_active(kind,r.inspect(active[kind]['id']))
    r.healthy_pair(active)

def write_file(path,data,metadata):
    # Container bind mounts point to directories, so rename is visible inside them.
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as out:
            os.fchown(out.fileno(),metadata['uid'],metadata['gid'])
            os.fchmod(out.fileno(),metadata['mode'])
            out.write(data);out.flush();os.fsync(out.fileno())
        os.replace(tmp,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def phase(record,value):
    record['phase']=value;r.putjson(PENDING,record);r.putjson(Path(record['journal'])/'transaction.json',record)
    print('CONFIG_PHASE: '+value,flush=True)

def rollback(record):
    phase(record,'rollback_requested')
    active=r.readjson(r.ACTIVE)
    need({k:v['id'] for k,v in active.items()}=={k:v['id'] for k,v in record['active'].items()},'Container IDs changed during deployment')
    stopped(active) # If this fails, no old file is restored and no container is started.
    for filename,meta in record['old'][record['kind']]['files'].items():
        data=(Path(record['journal'])/'old'/filename).read_bytes()
        need(sha(data)==meta['sha256'],'Rollback snapshot drift')
        write_file(Path(meta['path']),data,meta)
    r.putjson(r.ACTIVE,record['active']);r.putjson(CURRENT,record['old'])
    started(record['active'])
    phase(record,'rolled_back');PENDING.unlink()
    print('MAIL_CONFIG_ROLLBACK_OK',flush=True)

def deploy(kind,release):
    manifest=verify_release(release,kind);active=check_active();old=r.readjson(CURRENT)
    for k in r.SERVICES: check_files(old[k])
    r.healthy_pair(active)
    for filename,meta in old[kind]['files'].items():
        need(targets(kind,r.inspect(active[kind]['id']))[filename]==Path(meta['path']),'Config mount mapping changed')
    new=json.loads(json.dumps(old));new[kind]['release']=str(release);new[kind]['revision']=manifest['revision']
    same=all(meta['sha256']==manifest['rendered'][filename] for filename,meta in old[kind]['files'].items())
    if same:
        r.putjson(CURRENT,new)
        print('MAIL_CONFIG_NOOP: '+kind+' '+manifest['revision']+'; no restart',flush=True);return
    journal=Path(tempfile.mkdtemp(prefix='config-deploy-',dir=STATE))
    r.COMMAND_LOG=journal/'command-errors.log'
    for filename,meta in old[kind]['files'].items():
        data=Path(meta['path']).read_bytes();need(sha(data)==meta['sha256'],'Configuration changed before snapshot')
        r.atomic(journal/'old'/filename,data)
    record={'kind':kind,'journal':str(journal),'release':str(release),'old':old,'active':active}
    phase(record,'prepared')
    try:
        stopped(active);phase(record,'stopped')
        for filename,meta in old[kind]['files'].items():
            write_file(Path(meta['path']),(release/filename).read_bytes(),meta)
        phase(record,'files_written')
        started(active)
        for filename,meta in old[kind]['files'].items():
            updated=file_record(Path(meta['path']))
            need(updated['sha256']==manifest['rendered'][filename],'Application changed deployed configuration')
            new[kind]['files'][filename]=updated
        r.putjson(CURRENT,new)
        phase(record,'completed');PENDING.unlink()
        print('MAIL_CONFIG_DEPLOY_OK: '+kind+' '+manifest['revision'],flush=True)
    except BaseException:
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP): signal.signal(sig,signal.SIG_IGN)
        try: rollback(record)
        except BaseException:
            phase(record,'rollback_failed');print('MAIL_CONFIG_ROLLBACK_FAILED: '+str(PENDING),file=sys.stderr)
        raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','apply','status','recover','enable','disable'])
    parser.add_argument('service',nargs='?',choices=r.SERVICES)
    parser.add_argument('revision',nargs='?')
    args=parser.parse_args();need(os.geteuid()==0,'Run as root');os.umask(0o077)
    if args.action in ('prepare','apply'):
        need(args.service and args.revision and re.fullmatch('[0-9a-f]{40}',args.revision),'Full lowercase Git revision required')
    else: need(args.service is None and args.revision is None,'Unexpected arguments')
    with r.locks(allow_config_pending=True):
        need(not r.PENDING.exists(),'Pending mail migration')
        if args.action=='recover':
            need(PENDING.exists(),'No pending configuration deployment');rollback(r.readjson(PENDING));return
        need(not PENDING.exists(),'Pending configuration deployment; use ac-mail-config recover')
        if args.action in ('enable','disable'):
            if args.action=='enable':
                check_active()
                for entry in r.readjson(CURRENT).values(): check_files(entry)
                r.atomic(ENABLED,b'Enabled by administrator\n')
            else: ENABLED.unlink(missing_ok=True)
            print('MAIL_CONFIG_CI_'+args.action.upper()+'D');return
        if args.action=='status':
            active=check_active(False)
            for kind,entry in r.readjson(CURRENT).items():
                check_files(entry);print(kind+': '+entry['revision'])
            print('CI_DEPLOY_ENABLED='+str(ENABLED.exists()).lower());return
        if args.action=='apply': need(ENABLED.is_file(),'Automatic deployment not enabled')
        release=prepare(args.service,args.revision)
        if args.action=='apply': deploy(args.service,release)
        else: print('PRODUCTION_UNCHANGED')

if __name__=='__main__':
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP): signal.signal(sig,r.interrupted)
    try: main()
    except Exception as e:
        print('MAIL_CONFIG_ERROR: '+(str(e) if isinstance(e,(RuntimeError,r.releases.Failure)) else type(e).__name__),file=sys.stderr)
        sys.exit(1)
