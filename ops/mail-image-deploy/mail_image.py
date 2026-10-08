#!/usr/bin/python3
"""Reviewed mail image pair deployment; root only, no automatic CI activation."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import sys
import tempfile

sys.path.insert(0, '/usr/local/libexec/ac-mail-switch')
sys.path.insert(0, '/usr/local/libexec/ac-mail-config')
import mail_runtime as r
import mail_config as c

STATE = r.STATE
PENDING = STATE/'pending-image.json'
LAST = STATE/'last-image.json'
APPROVED = {
    'dovecot': ('4f3340e7aca41210ae3292a8d629f9fb34ee6f1d',
                '4cb832a8b175d71f3378486a0885d8ebd6c0062b5b2fef9f0451d32e9668f43d'),
    'postfix': ('bb9df19a40b3161e55c6d97460450449dd2638bf',
                'dac5f06d537914bd8f91f8cc0076dc19c3d27df958ff4f7d544d7bad54c83079'),
}
need = r.require

def protected(path, directory=False):
    c.safe_parents(path)
    return c.safe(path, directory)

def image_info(image):
    return json.loads(r.pod('image','inspect',image).stdout)[0]

def candidate_image(kind):
    revision, image = APPROVED[kind]
    receipt = STATE/'image-imports'/kind/(revision+'.json')
    protected(receipt)
    expected = {'revision':revision, 'image':'localhost/'+kind+'-ac:'+revision,
                'image_id':'sha256:'+image}
    need(r.readjson(receipt)==expected, 'Import receipt differs: '+kind)
    info = image_info(expected['image'])
    cfg = info['Config']
    need(info['Id'].removeprefix('sha256:')==image, 'Imported tag changed')
    need(info['Os']=='linux' and info['Architecture']=='amd64', 'Wrong image platform')
    need(cfg.get('Labels',{}).get('org.opencontainers.image.revision')==revision,'Wrong revision')
    need(cfg.get('User') in ('root','0','0:0') and not cfg.get('Entrypoint'), 'Wrong image identity/entrypoint')
    need(cfg.get('Cmd')==r.OLD[kind]['cmd'] and not cfg.get('Volumes'), 'Wrong image command/volumes')
    need(cfg.get('StopSignal') in ('SIGTERM','TERM',15), 'Wrong stop signal')
    return image

def phase(record, value):
    record['phase']=value
    r.putjson(PENDING,record)
    r.putjson(Path(record['journal'])/'transaction.json',record)
    print('MAIL_IMAGE_PHASE: '+value,flush=True)

def config_tree(kind, old, journal):
    mounts={m['Destination']:Path(m['Source']) for m in old['Mounts']}
    result={}
    destinations=['/etc/'+kind]
    if kind=='dovecot': destinations.append('/run/secrets/dovecot')
    for index,dest in enumerate(destinations):
        source=mounts[dest]
        need(source.resolve()==source and source.is_relative_to(STATE),'Unexpected working config path')
        target=journal/(kind+'-config-'+str(index))
        # cp -a retains Postfix's absolute makedefs.out link, modes and ownership.
        r.run(['cp','-a','--',str(source),str(target)])
        result[dest]=str(target)
    return result

def create_args(kind, old, image, mounts, token):
    h=old['HostConfig'];cfg=old['Config']
    need(not cfg.get('Entrypoint'),'Unexpected entrypoint')
    need(not h.get('Privileged') and not h.get('ReadonlyRootfs') and not h.get('UsernsMode'), 'Unsupported isolation')
    need(not any(h.get(k) for k in ('SecurityOpt','CapAdd','CapDrop','Devices','BindsFrom','VolumesFrom')), 'Unsupported host options')
    args=['create','--pull=never','--name',r.name(kind),
          '--label','ac.mail.image-transaction='+token,
          '--network','ac_network','--ip',r.OLD[kind]['ip'],
          '--ip6',r.OLD[kind]['ip6'],'--mac-address',r.MAC[kind],
          '--restart=no','--stop-signal=SIGTERM','--stop-timeout=120','--user=root']
    for value in cfg.get('Env') or []: args+=['--env',value]
    if cfg.get('WorkingDir'): args+=['--workdir',cfg['WorkingDir']]
    if cfg.get('Hostname'): args+=['--hostname',cfg['Hostname']]
    args+=['--shm-size',str(h['ShmSize']),'--memory',str(h['Memory']),
           '--pids-limit',str(h['PidsLimit']),'--log-driver',h['LogConfig']['Type']]
    for key,value in (h['LogConfig'].get('Config') or {}).items(): args+=['--log-opt',key+'='+str(value)]
    for limit in h.get('Ulimits') or []:
        key=limit['Name'].lower().removeprefix('rlimit_')
        args+=['--ulimit',key+'='+str(limit['Soft'])+':'+str(limit['Hard'])]
    for port,bindings in (h.get('PortBindings') or {}).items():
        for binding in bindings:
            host=binding['HostIp'];host='['+host+']' if ':' in host else host
            args+=['-p',host+':'+binding['HostPort']+':'+port]
    for mount in old['Mounts']:
        need(mount['Type']=='bind','Unexpected volume type')
        dest=mount['Destination'];src=mounts.get(dest,mount['Source'])
        need(not any(x in src+dest for x in (':','\n',',')), 'Unsupported mount path')
        args+=['--mount','type=bind,source='+src+',destination='+dest+',ro='+str(not mount['RW']).lower()]
    return args+[image,*cfg['Cmd']]

def verify_new(kind, actual, record):
    old=record['old'][kind];cfg=actual['Config']
    need(actual['Name'].lstrip('/')==r.name(kind),'Wrong name')
    need(actual['Image'].removeprefix('sha256:')==record['images'][kind], 'Wrong candidate image')
    need(cfg.get('Labels',{}).get('ac.mail.image-transaction')==record['token'],'Wrong transaction label')
    expected=r.fingerprint(old)
    expected.update(id=actual['Id'],image=record['images'][kind],user='root')
    expected['mounts']=sorted((record['mounts'][kind].get(m['Destination'],m['Source']),
                              m['Destination'],m['RW'],m['Type']) for m in old['Mounts'])
    need(r.fingerprint(actual)==expected,'Candidate settings differ: '+kind)
    need(cfg.get('Hostname')==old['Config'].get('Hostname'),'Hostname differs')
    need(actual['HostConfig']['RestartPolicy']['Name'] in ('no','never',''),'Competing restart policy')
    need(cfg.get('StopSignal') in ('SIGTERM','TERM',15) and cfg.get('StopTimeout')==120,'Wrong stop behavior')

def mapped_state(record, active):
    result=copy.deepcopy(record['config'])
    for kind in r.SERVICES:
        mapping=c.targets(kind,r.inspect(active[kind]['id']))
        for filename,meta in result[kind]['files'].items():
            now=c.file_record(mapping[filename])
            need(all(now[k]==meta[k] for k in ('sha256','uid','gid','mode')), 'Copied config changed: '+filename)
            result[kind]['files'][filename]=now
    return result

def validate_configs(active, configs, images, report):
    for kind in r.SERVICES:
        root=report/('validation-'+kind);root.mkdir(mode=0o700)
        mapping=c.targets(kind,r.inspect(active[kind]['id']))
        need(set(mapping)==set(configs[kind]['files']),'Config file list differs')
        for filename,path in mapping.items():
            need(str(path)==configs[kind]['files'][filename]['path'],'Configuration mapping differs')
            r.atomic(root/filename,path.read_bytes())
        r.releases.validate(kind,root,image=images[kind])
        print('MAIL_IMAGE_CONFIG_TEST_OK: '+kind,flush=True)

def storage_paths(old):
    mounts={m['Destination']:Path(m['Source']) for m in old['postfix']['Mounts']}
    paths=[r.MAIL,r.SPOOL,mounts['/var/lib/postfix']]
    for path in paths:
        need(path.is_absolute() and path.resolve()==path and path.is_dir(),'Unsafe storage path')
    need(len(set(paths))==3,'Overlapping data paths')
    return paths

def exclusive_storage(old,paths):
    ids=r.pod('ps','-aq').stdout.split()
    owners={v['Id'] for v in old.values()}
    for info in json.loads(r.pod('inspect',*ids).stdout) if ids else []:
        if not info['State']['Running'] or info['Id'] in owners: continue
        for mount in info.get('Mounts',[]):
            if mount.get('Type')!='bind': continue
            source=Path(os.path.realpath(mount['Source']))
            need(not any(source==p or source.is_relative_to(p) or p.is_relative_to(source) for p in paths),
                 'Another running container uses mail storage')

def preflight(report):
    need(not r.PENDING.exists() and not c.PENDING.exists(),'Pending mail transaction')
    active=c.check_active();configs=r.readjson(c.CURRENT)
    for entry in configs.values(): c.check_files(entry)
    old={kind:r.inspect(active[kind]['id']) for kind in r.SERVICES}
    for kind in r.SERVICES:
        need(old[kind]['Image'].removeprefix('sha256:')==r.releases.SPEC[kind]['image'],
             'This reviewed upgrade requires the original production image: '+kind)
        need(old[kind]['Config']['Cmd']==r.OLD[kind]['cmd'],'Unexpected command')
        need(not (r.service_dir(kind)/'down').exists(),'Supervisor deliberately down')
        r.verify_supervised(kind,old[kind])
    images={kind:candidate_image(kind) for kind in r.SERVICES}
    for kind in r.SERVICES: create_args(kind,old[kind],images[kind],{},'preflight')
    r.healthy_pair(active);r.pg_health();r.idle_legacy()
    for short in ('start','stop'):
        expected=(r.LIB/'legacy'/(short+'.after')).read_bytes()
        need((r.LEGACY_BIN/(short+'_ac_containers.sh')).read_bytes()==expected,'Legacy guard changed')
        need((r.PG/(short+'.after')).read_bytes()==expected,'PostgreSQL guard changed')
    protected(Path('/var/backups/ac-mail'),True)
    r.check_storage();paths=storage_paths(old);exclusive_storage(old,paths)
    # Refuse nested filesystems beneath all three data trees, including Postfix data.
    def walk(entries):
        for item in entries:
            target=Path(item.get('target','/'))
            need(not any(target==p or target.is_relative_to(p) for p in paths),'Nested filesystem needs reviewed backup')
            walk(item.get('children',[]))
    walk(json.loads(r.run(['findmnt','--json','--output','TARGET']).stdout)['filesystems'])
    size=sum(int(r.run(['du','-s','-B1','--',str(p)]).stdout.split()[0]) for p in paths)
    need(shutil.disk_usage('/var/backups/ac-mail').free>size*2+1024**3,'Insufficient backup space')
    validate_configs(active,configs,images,report)
    print('MAIL_IMAGE_PREFLIGHT_OK: production unchanged',flush=True)
    return active,configs,old,images

def cold_backup(record):
    for kind in r.SERVICES: need(not r.inspect(record['old'][kind]['Id'])['State']['Running'],'Backup requires stopped pair')
    paths=storage_paths(record['old']);exclusive_storage(record['old'],paths)
    dest=Path(record['backup']);dest.mkdir(mode=0o700)
    archive=dest/'mail-queue-data.tar'
    r.run(['tar','--acls','--xattrs','--numeric-owner','-cpf',str(archive),'-C','/',
           *[str(p).lstrip('/') for p in paths]],timeout=1800)
    r.run(['tar','-tf',str(archive)],timeout=300)
    r.run(['sync','-f',str(archive)])
    digest=hashlib.sha256()
    with archive.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''): digest.update(block)
    r.atomic(dest/'SHA256SUMS',(digest.hexdigest()+'  mail-queue-data.tar\n').encode())
    for kind in r.SERVICES: need(not r.inspect(record['old'][kind]['Id'])['State']['Running'],'Unexpected restart during backup')
    print('MAIL_IMAGE_COLD_BACKUP_OK: '+str(dest),flush=True)

def discover(record,kind):
    cid=record['candidates'].get(kind)
    if cid: return cid
    found=r.pod('container','exists',r.name(kind),check=False)
    need(found.returncode in (0,1),'Cannot inspect service name')
    if found.returncode==1: return None
    info=r.inspect(r.name(kind))
    if info['Id']==record['old'][kind]['Id']: return None
    need(info['Config'].get('Labels',{}).get('ac.mail.image-transaction')==record['token'],
         'Unknown container owns service name; refusing to touch it')
    need(info['Image'].removeprefix('sha256:')==record['images'][kind],'Unknown candidate image')
    record['candidates'][kind]=info['Id'];phase(record,'rollback_requested')
    return info['Id']

def rollback(record):
    phase(record,'rollback_requested')
    # Stop every candidate before either old instance can write to shared data.
    for kind in reversed(r.SERVICES):
        r.pause(kind)
        cid=discover(record,kind)
        if cid:
            info=r.inspect(cid)
            need(info['Config'].get('Labels',{}).get('ac.mail.image-transaction')==record['token'] and
                 info['Image'].removeprefix('sha256:')==record['images'][kind],'Wrong rollback stop target')
            r.stop_id(cid,clean=False)
        old=r.inspect(record['old'][kind]['Id'])
        need(r.fingerprint(old)==r.fingerprint(record['old'][kind]),'Original container drift')
        r.stop_id(old['Id'])
    # Never overwrite a configuration that changed since the snapshot.
    for entry in record['config'].values(): c.check_files(entry)
    for kind in r.SERVICES:
        cid=record['candidates'].get(kind)
        if cid and r.inspect(cid)['Name'].lstrip('/')==r.name(kind):
            r.pod('rename',cid,r.name(kind)+'-failed-'+record['token'])
        old=r.inspect(record['old'][kind]['Id'])
        if old['Name'].lstrip('/')!=r.name(kind): r.pod('rename',old['Id'],r.name(kind))
    r.putjson(r.ACTIVE,record['active']);r.putjson(c.CURRENT,record['config'])
    for kind in r.SERVICES:
        r.up(kind);r.wait_health(kind,record['active'][kind]['id'])
        r.verify_active(kind,r.inspect(record['active'][kind]['id']))
        r.verify_supervised(kind,r.inspect(record['active'][kind]['id']))
    r.healthy_pair(record['active']);r.pg_health()
    phase(record,'rolled_back');PENDING.unlink()
    print('MAIL_IMAGE_ROLLBACK_OK: original containers running',flush=True)

def deploy(report):
    active,configs,old,images=preflight(report)
    journal=Path(tempfile.mkdtemp(prefix='image-deploy-',dir=STATE))
    r.COMMAND_LOG=journal/'command-errors.log'
    mounts={kind:config_tree(kind,old[kind],journal) for kind in r.SERVICES}
    record={'format':1,'token':journal.name,'journal':str(journal),
            'active':active,'config':configs,'old':old,'images':images,'mounts':mounts,
            'candidates':{},'backup':'/var/backups/ac-mail/'+journal.name}
    phase(record,'prepared')
    try:
        for kind in reversed(r.SERVICES):
            r.verify_active(kind,r.inspect(active[kind]['id']))
            r.pause(kind);r.stop_id(active[kind]['id'])
        phase(record,'stopped_cleanly');cold_backup(record);phase(record,'backed_up')
        # Verify managed config after stop as well, before constructing candidates.
        for entry in configs.values(): c.check_files(entry)
        for kind in r.SERVICES:
            r.pod('rename',old[kind]['Id'],r.name(kind)+'-rollback-'+record['token'])
            cid=r.pod(*create_args(kind,old[kind],images[kind],mounts[kind],record['token'])).stdout.strip()
            record['candidates'][kind]=cid;phase(record,kind+'_created')
            verify_new(kind,r.inspect(cid),record)
        new=copy.deepcopy(active)
        for kind in r.SERVICES:
            cid=record['candidates'][kind]
            new[kind].update(id=cid,fingerprint=r.fingerprint(r.inspect(cid)))
        new_config=mapped_state(record,new)
        record['new_active']=new;record['new_config']=new_config;phase(record,'ready_to_start')
        r.putjson(r.ACTIVE,new);r.putjson(c.CURRENT,new_config)
        for kind in r.SERVICES:
            r.up(kind);r.wait_health(kind,new[kind]['id'])
            r.verify_active(kind,r.inspect(new[kind]['id']))
            r.verify_supervised(kind,r.inspect(new[kind]['id']))
        for entry in new_config.values(): c.check_files(entry)
        r.healthy_pair(new);r.pg_health()
        phase(record,'completed');r.putjson(LAST,record);PENDING.unlink()
        print('MAIL_IMAGE_DEPLOY_OK: '+str(journal),flush=True)
    except BaseException:
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP): signal.signal(sig,signal.SIG_IGN)
        try: rollback(record)
        except BaseException:
            phase(record,'rollback_failed')
            print('MAIL_IMAGE_ROLLBACK_FAILED: '+str(PENDING),file=sys.stderr)
        raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['check','deploy','recover','rollback','status'])
    args=parser.parse_args();need(os.geteuid()==0,'Run as root');os.umask(0o077)
    protected(STATE,True)
    with r.locks(allow_image_pending=True):
        need(not r.PENDING.exists() and not c.PENDING.exists(),'Pending other mail transaction')
        if args.action=='recover':
            protected(PENDING);record=r.readjson(PENDING)
            r.COMMAND_LOG=Path(record['journal'])/'command-errors.log'
            rollback(record);return
        need(not PENDING.exists(),'Pending image deployment; use recover')
        if args.action=='rollback':
            protected(LAST);record=r.readjson(LAST)
            active=c.check_active()
            need(active==record['new_active'] and r.readjson(c.CURRENT)==record['new_config'],
                 'Active image/config state changed after deployment; manual rollback refused')
            for entry in record['new_config'].values(): c.check_files(entry)
            r.COMMAND_LOG=Path(record['journal'])/'command-errors.log'
            rollback(record);return
        if args.action=='status':
            active=c.check_active(False)
            for kind in r.SERVICES: print(kind+': '+active[kind]['fingerprint']['image'])
            return
        report=Path(tempfile.mkdtemp(prefix='image-check-',dir=STATE))
        r.COMMAND_LOG=report/'command-errors.log';print('REPORT='+str(report),flush=True)
        if args.action=='check': preflight(report)
        else: deploy(report)

if __name__=='__main__':
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP): signal.signal(sig,r.interrupted)
    try: main()
    except Exception as error:
        print('MAIL_IMAGE_ERROR: '+(str(error) if isinstance(error,(RuntimeError,r.releases.Failure)) else type(error).__name__),file=sys.stderr)
        sys.exit(1)
