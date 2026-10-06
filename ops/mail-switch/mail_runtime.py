#!/usr/bin/python3
"""One-time transactional migration of the reviewed AC mail pair."""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import smtplib
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import mail_release as releases

STATE=Path('/var/lib/ac-mail')
LIB=Path('/usr/local/libexec/ac-mail-switch')
PG=Path('/usr/local/libexec/ac-postgresql/legacy')
MARKER=Path('/etc/ac/managed/mail')
PENDING=STATE/'pending-switch.json'
ACTIVE=STATE/'active.json'
PGLOCK=Path('/var/lib/ac-postgresql/lock')
PGPENDING=Path('/var/lib/ac-postgresql/pending-config-deploy.json')
COMMAND_LOG=None
LEGACY_BIN=Path('/usr/bin')
POD='/usr/local/bin/podman'
ENV={'HOME':'/root','PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8'}
MAIL=Path('/var/volumes/data/dovecot_container_openmailserver.net/var/mail')
SPOOL=Path('/var/volumes/data/postfix_container_openmailserver.net/var/spool')
CERTS=Path('/var/volumes/data/letsencrypt_container_openmailserver.net/etc/letsencrypt')
SERVICES=('dovecot','postfix')
OLD={
 'dovecot':{'id':'d24987b4fc8532b009d6dc2f910ef46170554998c08a09aea3ef8c4e6c0c9922','ip':'10.89.1.213','ip6':'fd00:10:89:1::213','ports':(993,995),'cmd':['dovecot','-F']},
 'postfix':{'id':'5a603ae96a5d6269c4abfadae4dd2064999c2d89ddff607377c81b8a4237400b','ip':'10.89.1.215','ip6':'fd00:10:89:1::215','ports':(25,587,465),'cmd':['postfix','start-fg']},
}
MAC={'dovecot':'1a:77:d8:6c:a6:ce','postfix':'02:ac:10:89:01:d7'}

def require(ok,msg):
    if not ok: raise RuntimeError(msg)
def name(service): return service+'_container_openmailserver.net'
def unit(service): return 'ac-'+service+'-runit.service'
def service_dir(service): return Path('/etc/ac/runit')/service

def run(args,check=True,timeout=120):
    p=subprocess.run(args,env=ENV,cwd='/',text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if p.returncode and COMMAND_LOG is not None:
        with COMMAND_LOG.open('a') as log:
            log.write(Path(args[0]).name+' exit='+str(p.returncode)+'\n'+p.stdout+p.stderr+'\n')
    if check and p.returncode: raise RuntimeError('Command failed: '+Path(args[0]).name+'; see private command-errors.log')
    return p

def pod(*args,**kw): return run([POD,'--remote=false',*args],**kw)
def inspect(cid): return json.loads(pod('inspect',cid).stdout)[0]
def atomic(path,data,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),mode);f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        fd=os.open(path.parent,os.O_DIRECTORY|os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
def putjson(path,obj): atomic(path,(json.dumps(obj,indent=2)+'\n').encode())
def readjson(path): return json.loads(path.read_text())
HOST_KEYS=('PortBindings','ShmSize','Memory','PidsLimit','Ulimits','Privileged','SecurityOpt','CapAdd','CapDrop','UsernsMode')
def host_settings(c):
    h=c['HostConfig'];result={k:h.get(k) for k in HOST_KEYS}
    for k in ('Ulimits','SecurityOpt','CapAdd','CapDrop'):
        result[k]=sorted(h.get(k) or [],key=lambda value:json.dumps(value,sort_keys=True))
    result['PortBindings']={k:sorted(v or [],key=lambda value:json.dumps(value,sort_keys=True)) for k,v in (h.get('PortBindings') or {}).items()}
    return result

def fingerprint(c):
    cfg=c['Config'];h=c['HostConfig']
    return {'id':c['Id'],'image':c['Image'].removeprefix('sha256:'),
            'cmd':cfg['Cmd'],'user':cfg.get('User',''),'entrypoint':cfg.get('Entrypoint'),
            'env':sorted(cfg.get('Env') or []),'workingdir':cfg.get('WorkingDir',''),
            'host':host_settings(c),
            'mounts':sorted((m['Source'],m['Destination'],m['RW'],m['Type']) for m in c['Mounts'])}
def verify_active(s,c):
    active=readjson(ACTIVE)[s]
    # JSON serializes tuples as lists.
    require(json.loads(json.dumps(fingerprint(c)))==active['fingerprint'],'Container differs from active manifest: '+s)
    require(c['Name'].lstrip('/')==name(s),'Unexpected active name')
    require(c['HostConfig']['RestartPolicy']['Name'] in ('no','never',''),'Competing restart policy')
    if c['State']['Running']:
        nets=c['NetworkSettings']['Networks'];require(set(nets)=={'ac_network'},'Unexpected active network')
        n=nets['ac_network']
        require((n['IPAddress'],n['GlobalIPv6Address'],n['MacAddress'].lower())==(OLD[s]['ip'],OLD[s]['ip6'],MAC[s]),'Active network differs')

def stop_id(cid,clean=True):
    c=inspect(cid);require(c['Id']==cid,'Wrong stop target')
    require(c['HostConfig']['RestartPolicy']['Name'] in ('no','never',''),'Disable restart policy before stopping')
    if c['State']['Running']: pod('kill','--signal','TERM',cid)
    for _ in range(120):
        c=inspect(cid)
        if not c['State']['Running']:
            require(not clean or (not c['State'].get('OOMKilled',False) and (c['State']['Status']=='created' or c['State']['ExitCode']==0)),'Unclean shutdown')
            return
        time.sleep(1)
    raise RuntimeError('Shutdown timeout; no SIGKILL sent')

def basic_health(s,cid):
    c=inspect(cid);require(c['State']['Running'],'Container not running')
    if s=='dovecot':
        pod('exec',cid,'doveconf','-n')
        text=pod('exec',cid,'doveadm','user','eugene@belov.email',timeout=15).stdout
        fields=dict(line.split(None,1) for line in text.splitlines() if len(line.split(None,1))==2)
        expected={'uid':'55004','gid':'55004','home':'/var/mail/belov.email/eugene','mail':'maildir:/var/mail/belov.email/eugene'}
        require(all(fields.get(k)==v for k,v in expected.items()),'Dovecot userdb health failed')
    else:
        pod('exec',cid,'postfix','status')
        require(pod('exec',cid,'postconf','-h','virtual_transport').stdout.strip()=='lmtp:inet:10.89.1.213:24','Wrong LMTP target')

def wait_health(s,cid):
    for attempt in range(20):
        try: basic_health(s,cid);return
        except Exception:
            if attempt==19: raise
            time.sleep(2)

def pg_health():
    # Caller holds the PostgreSQL lock; do not invoke its locking CLI recursively.
    source=PG.parent/'ac-pg-runtime.py'
    spec=importlib.util.spec_from_file_location('ac_pg_runtime_for_mail',source)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.load_active();module.healthy()
    require(all(module.script_status()),'PostgreSQL legacy guards differ')

def tls_probe(port,implicit):
    ctx=ssl.create_default_context()
    if implicit:
        with socket.create_connection(('93.115.20.205',port),10) as raw:
            with ctx.wrap_socket(raw,server_hostname='openmailserver.net') as conn:
                require(conn.recv(1024).startswith(b'220' if port==465 else (b'+OK' if port==995 else b'* OK')),'Missing TLS greeting')
    else:
        with smtplib.SMTP('93.115.20.205',port,timeout=10) as smtp:
            smtp._host='openmailserver.net'
            smtp.ehlo();smtp.starttls(context=ctx);smtp.ehlo()
            require(smtp.has_extn('auth'),'Missing submission AUTH')

def healthy_pair(active):
    for s in SERVICES: basic_health(s,active[s]['id'])
    tls_probe(993,True);tls_probe(995,True);tls_probe(587,False);tls_probe(465,True)
    with smtplib.SMTP('93.115.20.205',25,timeout=10) as smtp:
        smtp.ehlo();require(not smtp.has_extn('auth'),'AUTH on port 25')
        require(smtp.mail('')[0]==250,'MAIL FROM failed')
        require(smtp.rcpt('eugene@belov.email')[0]==250,'Known recipient rejected')
        smtp.rset();require(smtp.mail('')[0]==250,'MAIL FROM failed')
        require(smtp.rcpt('probe@example.org')[0]==554,'Relay protection failed')
        smtp.rset()

def old_scripts():
    for short in ('start','stop'):
        expected=(LIB/'legacy'/(short+'.before')).read_bytes()
        require((LEGACY_BIN/(short+'_ac_containers.sh')).read_bytes()==expected,'Legacy script differs: '+short)
        require((PG/(short+'.after')).read_bytes()==expected,'PostgreSQL reference differs: '+short)

def idle_legacy():
    status=run(['systemctl','show','ac_containers.service','-p','ActiveState','-p','SubState']).stdout
    require('ActiveState=active' in status and 'SubState=exited' in status,'Legacy service not idle active/exited')
    p=run(['pgrep','-f',r'^(/bin/bash|/usr/bin/bash) /usr/bin/(start|stop)_ac_containers.sh( |$)'],check=False)
    require(p.returncode==1,'Legacy launcher running or pgrep failed')

def expected_mounts(s):
    result={'/etc/'+s:'/root/git/containers_etc/'+name(s)+'/etc/'+s,
            '/var/log':'/var/volumes/log/'+name(s)+'/var/log','/etc/letsencrypt':str(CERTS),'/var/mail':str(MAIL)}
    if s=='postfix': result['/var/spool']=str(SPOOL)
    return result

def verify_reference(root=LIB):
    for filename,expected in readjson(root/'reference-sha256.json').items():
        path=Path(filename)
        require(path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest()==expected,
                'Installed PostgreSQL/legacy reference differs: '+filename)

def preflight(paths):
    require(not PENDING.exists() and not ACTIVE.exists() and not MARKER.exists(),'Already managed or pending transaction')
    verify_reference();old_scripts();idle_legacy()
    pg_health()
    for executable in ('/usr/bin/runsv','/usr/bin/sv','/usr/bin/svlogd'): require(Path(executable).is_file(),'Missing '+executable)
    require(shutil.disk_usage('/var/backups').free > 3*1024**3,'Less than 3 GiB free for backup')
    result={}
    for s in SERVICES:
        require(paths[s].is_absolute() and paths[s].resolve()==paths[s] and paths[s].parent==STATE/'releases'/s,'Unexpected release path')
        for parent in paths[s].parents:
            st=parent.lstat();require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,'Unsafe release ancestor')
        releases.verify_release(paths[s],s)
        c=inspect(name(s));spec=OLD[s]
        require(c['Id']==spec['id'] and c['Image'].removeprefix('sha256:')==releases.SPEC[s]['image'],'Unreviewed original container/image')
        require(c['State']['Running'] and c['Config']['Cmd']==spec['cmd'],'Original not running/command differs')
        require(c['Config'].get('Entrypoint') in (None,[]),'Unexpected entrypoint')
        require(c['HostConfig']['RestartPolicy']['Name']=='always','Unexpected original restart policy')
        mounts={m['Destination'].rstrip('/'):os.path.normpath(m['Source']) for m in c['Mounts']}
        require(mounts==expected_mounts(s) and all(m['Type']=='bind' and m['RW'] for m in c['Mounts']),'Unexpected original mounts')
        nets=c['NetworkSettings']['Networks'];require(set(nets)=={'ac_network'},'Unexpected network')
        n=nets['ac_network'];require(n['IPAddress']==spec['ip'] and n['GlobalIPv6Address']==spec['ip6'],'Unexpected original IP')
        h=c['HostConfig']
        require(not any(h.get(k) for k in ('Privileged','SecurityOpt','CapAdd','CapDrop','ReadonlyRootfs')),'Unexpected security settings')
        require(h.get('UsernsMode','')=='','Unexpected user namespace')
        require((service_dir(s)/'down').is_file(),'Supervisor must be installed down')
        require(run(['systemctl','is-active','--quiet',unit(s)],check=False).returncode!=0,'Supervisor already active')
        require(run(['systemctl','is-enabled','--quiet',unit(s)],check=False).returncode!=0,'Supervisor already enabled')
        basic_health(s,c['Id']);result[s]=c
    ids=pod('ps','-aq').stdout.split()
    for c in json.loads(pod('inspect',*ids).stdout):
        if c['State']['Running'] and c['Id'] not in [v['id'] for v in OLD.values()]:
            for m in c.get('Mounts',[]):
                if m.get('Type')!='bind': continue
                src=os.path.realpath(m.get('Source',''))
                require(not any(src==str(t) or src.startswith(str(t)+'/') or str(t).startswith(src+'/') for t in (MAIL,SPOOL)), 'Another running container uses mail storage')
        if c['State']['Running']:
            for n in c.get('NetworkSettings',{}).get('Networks',{}).values():
                require(n.get('MacAddress','').lower()!=MAC['postfix'],'New Postfix MAC already used')
    check_storage()
    print('MAIL_PREFLIGHT_OK: production unchanged',flush=True)
    return result

def check_storage():
    for path in (MAIL,SPOOL):
        require(path.is_dir() and not path.is_symlink() and path.resolve()==path,'Unsafe mail storage path')
    # Exclude nested filesystems so the backup cannot silently miss or cross them.
    def visit(items):
        for item in items:
            target=item.get('target','')
            require(not any(target==str(p) or target.startswith(str(p)+'/') for p in (MAIL,SPOOL)), 'Separate mail mount requires a reviewed backup procedure')
            visit(item.get('children',[]))
    visit(json.loads(run(['findmnt','--json','--output','TARGET']).stdout)['filesystems'])

def candidate_command(s,old,config,data):
    args=['create','--pull=never','--name',name(s),'--network','ac_network',
          '--ip',OLD[s]['ip'],'--ip6',OLD[s]['ip6'],'--mac-address',MAC[s],
          '--restart=no','--stop-signal=SIGTERM','--stop-timeout=120']
    for item in old['Config'].get('Env') or []: args+=['--env',item]
    if old['Config'].get('User'): args+=['--user',old['Config']['User']]
    if old['Config'].get('WorkingDir'): args+=['--workdir',old['Config']['WorkingDir']]
    # Preserve configured limits, not host-dependent defaults.
    h=old['HostConfig']
    args+=['--shm-size',str(h['ShmSize']),'--memory',str(h['Memory']),'--pids-limit',str(h['PidsLimit'])]
    for limit in h.get('Ulimits') or []:
        key=limit['Name'].lower().removeprefix('rlimit_')
        args+=['--ulimit',key+'='+str(limit['Soft'])+':'+str(limit['Hard'])]
    args+=['--log-driver',h['LogConfig']['Type']]
    for port, bindings in (h.get('PortBindings') or {}).items():
        for binding in bindings:
            host=binding['HostIp'];host='['+host+']' if ':' in host else host
            args+=['-p',host+':'+binding['HostPort']+':'+port]
    for m in old['Mounts']:
        dst=m['Destination'].rstrip('/')
        if s=='postfix' and dst=='/var/mail': continue
        src=os.path.normpath(m['Source']);mode='rw'
        if dst=='/etc/'+s:
            src=str(config/'config');mode='ro' if s=='dovecot' else 'rw'
        if dst=='/etc/letsencrypt': mode='ro'
        args+=['-v',src+':'+dst+':'+mode]
    if s=='dovecot': args+=['-v',str(config/'secrets')+':/run/secrets/dovecot:ro']
    else: args+=['-v',str(data)+':/var/lib/postfix:rw']
    args += [releases.SPEC[s]['image'],*OLD[s]['cmd']]
    return args

def verify_candidate(s,c,old,config,data):
    require(c['Image'].removeprefix('sha256:')==releases.SPEC[s]['image'],'Wrong candidate image')
    require(c['Name'].lstrip('/')==name(s),'Wrong candidate name')
    for key in ('Cmd','User','WorkingDir','Entrypoint'):
        require(c['Config'].get(key)==old['Config'].get(key),'Candidate differs: '+key)
    require(sorted(c['Config'].get('Env') or [])==sorted(old['Config'].get('Env') or []),'Candidate environment differs')
    actual_host=host_settings(c);expected_host=host_settings(old)
    for key in HOST_KEYS:
        require(actual_host[key]==expected_host[key],'Candidate differs: '+key)
    expected=expected_mounts(s)
    expected['/etc/'+s]=str(config/'config')
    if s=='postfix': expected.pop('/var/mail');expected['/var/lib/postfix']=str(data)
    else: expected['/run/secrets/dovecot']=str(config/'secrets')
    require({m['Destination'].rstrip('/'):os.path.normpath(m['Source']) for m in c['Mounts']}==expected,'Wrong candidate mounts')
    for m in c['Mounts']:
        ro=m['Destination'] in ('/etc/letsencrypt','/run/secrets/dovecot') or (s=='dovecot' and m['Destination']=='/etc/dovecot')
        require(m['Type']=='bind' and m['RW']==(not ro),'Wrong mount permissions')
    require(c['HostConfig']['RestartPolicy']['Name'] in ('no','never',''),'Candidate restart policy differs')
    require(c['Config'].get('StopSignal') in ('SIGTERM','TERM',15) and c['Config'].get('StopTimeout')==120,'Wrong stop behavior')

def phase(record,value):
    record['phase']=value;putjson(PENDING,record);putjson(Path(record['journal'])/'transaction.json',record)
    print('MAIL_PHASE: '+value,flush=True)

def set_legacy(after):
    for short in ('start','stop'):
        content=(LIB/'legacy'/(short+('.after' if after else '.before'))).read_bytes()
        allowed=[(LIB/'legacy'/(short+'.'+version)).read_bytes() for version in ('before','after')]
        for target,mode in (((LEGACY_BIN/(short+'_ac_containers.sh')),0o755),(PG/(short+'.after'),0o644)):
            require(target.read_bytes() in allowed,'Refusing to overwrite unrelated legacy edit: '+str(target))
            atomic(target,content,mode)

def pause(s):
    (service_dir(s)/'down').touch()
    run(['sv','-w','130','down',str(service_dir(s))],check=False,timeout=140)

def up(s):
    run(['systemctl','enable','--now',unit(s)])
    (service_dir(s)/'down').unlink(missing_ok=True)
    run(['sv','-w','130','up',str(service_dir(s))],timeout=140)

def rollback(record):
    phase(record,'rollback_requested')
    # Stop every possible candidate before restarting either original.
    for s in reversed(SERVICES):
        pause(s)
        cid=record.get('candidates',{}).get(s)
        if not cid:
            found=pod('container','exists',name(s),check=False)
            if found.returncode==0:
                c=inspect(name(s))
                if c['Id']!=OLD[s]['id']:
                    require(c['Config'].get('Labels',{}).get('ac.mail.transaction')==record['token'],'Unknown container owns service name')
                    cid=c['Id'];record['candidates'][s]=cid;phase(record,'rollback_requested')
        if cid:
            require(inspect(cid)['Config'].get('Labels',{}).get('ac.mail.transaction')==record['token'],'Wrong candidate transaction')
            stop_id(cid,clean=False)
    for s in SERVICES:
        run(['systemctl','stop',unit(s)],timeout=150)
        run(['systemctl','disable',unit(s)])
        cid=record.get('candidates',{}).get(s)
        if cid and inspect(cid)['Name'].lstrip('/')==name(s):
            pod('rename',cid,name(s)+'-failed-'+record['token'])
        old=inspect(OLD[s]['id']);require(old['Image']==record['old'][s]['Image'],'Original image changed')
        if old['Name'].lstrip('/')!=name(s): pod('rename',old['Id'],name(s))
    set_legacy(False);MARKER.unlink(missing_ok=True);ACTIVE.unlink(missing_ok=True)
    for s in SERVICES:
        pod('update','--restart=always',OLD[s]['id'])
        if not inspect(OLD[s]['id'])['State']['Running']: pod('start',OLD[s]['id'])
        wait_health(s,OLD[s]['id'])
    if record['timer_active']: run(['systemctl','start','ac_containers.timer'])
    phase(record,'rolled_back');PENDING.unlink();print('MAIL_ROLLBACK_OK: original containers running')

def build_config(s,path,journal):
    dest=journal/(s+'-release');dest.mkdir(mode=0o700)
    if s=='dovecot':
        shutil.copytree(path/'config',dest/'config');shutil.copytree(path/'secrets',dest/'secrets')
    else:
        scratch='ac-mail-config-base-'+journal.name
        pod('create','--pull=never','--network=none','--name',scratch,releases.SPEC[s]['image'])
        try: pod('cp',scratch+':/etc/postfix',str(dest/'config'))
        finally: pod('rm',scratch)
        for filename in ('main.cf','master.cf'): shutil.copy2(path/'config'/filename,dest/'config'/filename)
        maps=dest/'config/pgsql';maps.mkdir(exist_ok=True)
        # Resolve the actual package account in the pinned image.
        gid=int(pod('run','--rm','--pull=never','--network=none','--entrypoint=/usr/bin/id',releases.SPEC[s]['image'],'-g','postfix').stdout.strip())
        os.chown(maps,0,gid);os.chmod(maps,0o750)
        for src in (path/'secrets').iterdir():
            target=maps/src.name;shutil.copyfile(src,target);os.chown(target,0,gid);os.chmod(target,0o640)
    os.chmod(dest/'config',0o755)
    for filename in (('dovecot.conf',) if s=='dovecot' else ('main.cf','master.cf')): os.chmod(dest/'config'/filename,0o644)
    return dest

def backup(record):
    directory=Path(record['backup']);directory.mkdir(mode=0o700,parents=True)
    for s in SERVICES:
        require(not inspect(OLD[s]['id'])['State']['Running'],'Backup requires stopped mail pair')
    data=Path(record['data'])
    require(not data.exists(),'Data snapshot destination already exists')
    root=Path(pod('mount',OLD['postfix']['id']).stdout.strip())
    try:
        source=root/'var/lib/postfix'
        require(root.is_absolute() and source.is_dir() and not source.is_symlink(),'Unexpected Postfix data path')
        run(['cp','-a','--',str(source),str(data)])
        require((data.stat().st_uid,data.stat().st_gid)==(source.stat().st_uid,source.stat().st_gid),'Data ownership was not preserved')
    finally: pod('unmount',OLD['postfix']['id'])
    check_storage()
    # No writes to original mounts; tar preserves ownership, ACL and xattrs.
    targets=[str(MAIL).lstrip('/'),str(SPOOL).lstrip('/'),str(data).lstrip('/')]
    archive=directory/'mail-queue-data.tar'
    run(['tar','--acls','--xattrs','--numeric-owner','-cpf',str(archive),'-C','/',*targets],timeout=1800)
    run(['tar','-tf',str(archive)],timeout=300)
    h=hashlib.sha256()
    with archive.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
        os.fsync(f.fileno())
    atomic(directory/'SHA256SUMS',(h.hexdigest()+'  '+archive.name+'\n').encode())
    for s in SERVICES: require(not inspect(OLD[s]['id'])['State']['Running'],'Container restarted during backup')
    print('MAIL_COLD_BACKUP_OK: '+str(directory),flush=True)

def verify_supervised(s,c):
    conmon=c['State'].get('ConmonPid');require(conmon,'Missing conmon PID')
    require(unit(s) in Path('/proc/'+str(conmon)+'/cgroup').read_text(),'Conmon outside new supervisor')

def migrate(paths):
    original=preflight(paths)
    journal=Path(tempfile.mkdtemp(prefix='switch-',dir=STATE))
    configs={s:build_config(s,paths[s],journal) for s in SERVICES}
    record={'token':journal.name,'journal':str(journal),'old':original,'candidates':{},
            'releases':{s:str(paths[s]) for s in SERVICES},
            'data':str(journal/'postfix-data'),
            'backup':'/var/backups/ac-mail/'+journal.name,
            'timer_active':run(['systemctl','is-active','--quiet','ac_containers.timer'],check=False).returncode==0}
    phase(record,'prepared')
    try:
        run(['systemctl','stop','ac_containers.timer']);idle_legacy();old_scripts()
        set_legacy(True);atomic(MARKER,(str(journal)+'\n').encode())
        phase(record,'legacy_excluded')
        for s in reversed(SERVICES):
            pod('update','--restart=no',OLD[s]['id']);stop_id(OLD[s]['id'])
        phase(record,'stopped_cleanly');backup(record);phase(record,'backed_up')
        for s in SERVICES:
            pod('rename',OLD[s]['id'],name(s)+'-rollback-'+record['token'])
            args=candidate_command(s,original[s],configs[s],Path(record['data']))
            args[1:1]=['--label','ac.mail.transaction='+record['token']]
            cid=pod(*args).stdout.strip();record['candidates'][s]=cid;phase(record,s+'_created')
            verify_candidate(s,inspect(cid),original[s],configs[s],Path(record['data']))
        active={s:{'id':record['candidates'][s],'fingerprint':fingerprint(inspect(record['candidates'][s])),
                   'release':str(paths[s])} for s in SERVICES}
        putjson(ACTIVE,active)
        for s in SERVICES:
            up(s);wait_health(s,active[s]['id'])
            c=inspect(active[s]['id']);verify_active(s,c)
            n=c['NetworkSettings']['Networks']['ac_network'];require(n['MacAddress'].lower()==MAC[s],'Wrong candidate MAC')
            verify_supervised(s,c)
        healthy_pair(active)
        pg_health()
        if record['timer_active']: run(['systemctl','start','ac_containers.timer'])
        phase(record,'completed');PENDING.unlink()
        print('MAIL_SWITCH_OK: '+str(journal))
    except BaseException:
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP): signal.signal(sig,signal.SIG_IGN)
        try: rollback(record)
        except BaseException:
            phase(record,'rollback_failed');print('MAIL_ROLLBACK_FAILED: '+str(PENDING),file=sys.stderr)
        raise

@contextlib.contextmanager
def locks():
    with contextlib.ExitStack() as stack:
        for path in (STATE/'switch.lock',STATE/'release.lock',PGLOCK):
            f=stack.enter_context(path.open('a'));fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(not PGPENDING.exists(),'Pending PostgreSQL deployment')
        yield

def main():
    global COMMAND_LOG
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['check-legacy','migrate','recover','status','check','start','stop','restart','reload','run','signal-stop'])
    p.add_argument('--service',choices=SERVICES)
    p.add_argument('--dovecot-release',type=Path)
    p.add_argument('--postfix-release',type=Path)
    args=p.parse_args();require(os.geteuid()==0,'Run as root');os.umask(0o077)
    if args.action in ('run','signal-stop'):
        require(args.service,'Missing service');active=readjson(ACTIVE);cid=active[args.service]['id']
        if args.action=='signal-stop':
            try: stop_id(cid)
            except Exception: print('MAIL_STOP_FAILED: no SIGKILL sent',file=sys.stderr)
            return # successful control/t suppresses default runsv TERM of attached CLI
        require(MARKER.exists(),'Mail not adopted');c=inspect(cid);verify_active(args.service,c)
        require(not c['State']['Running'],'Already running outside supervisor')
        os.execve(POD,[POD,'--remote=false','start','--attach','--sig-proxy=false',cid],ENV)
    with locks():
        if args.action in ('check-legacy','migrate','recover'):
            report=Path(tempfile.mkdtemp(prefix='operation-',dir=STATE))
            COMMAND_LOG=report/'command-errors.log'
            print('REPORT='+str(report),flush=True)
        if args.action=='recover':
            require(PENDING.exists(),'No pending transaction');rollback(readjson(PENDING));return
        require(not PENDING.exists(),'Pending mail switch; use recover')
        if args.action in ('check-legacy','migrate'):
            paths={'dovecot':args.dovecot_release,'postfix':args.postfix_release}
            require(all(paths.values()),'Both releases are required')
            if args.action=='migrate': migrate(paths)
            else: preflight(paths)
        else:
            active=readjson(ACTIVE)
            for s in SERVICES:
                c=inspect(active[s]['id']);verify_active(s,c)
                print(s+': '+c['State']['Status'])
            if args.action in ('stop','restart'):
                for s in reversed(SERVICES):
                    pause(s);stop_id(active[s]['id'])
                print('MAIL_STOPPED')
            if args.action in ('start','restart'):
                for s in SERVICES: up(s);wait_health(s,active[s]['id'])
            if args.action=='reload':
                pod('exec',active['dovecot']['id'],'doveconf','-n')
                pod('exec',active['postfix']['id'],'postfix','check')
                pod('exec',active['dovecot']['id'],'dovecot','reload')
                pod('exec',active['postfix']['id'],'postfix','reload')
            if args.action in ('check','start','restart','reload'):
                healthy_pair(active);print('MAIL_HEALTH_OK')

def interrupted(signum,frame): raise RuntimeError('Interrupted')
if __name__=='__main__':
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP): signal.signal(sig,interrupted)
    try: main()
    except Exception as e:
        print('MAIL_RUNTIME_ERROR: '+(str(e) if isinstance(e,(RuntimeError,releases.Failure)) else type(e).__name__),file=sys.stderr)
        sys.exit(1)
