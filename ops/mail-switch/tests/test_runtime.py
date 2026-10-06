import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import mail_runtime as r
PG_HEALTH=r.pg_health


def container(service):
    h={'RestartPolicy':{'Name':'always'},'PortBindings':{str(p)+'/tcp':[{'HostIp':'93.115.20.205','HostPort':str(p)}] for p in r.OLD[service]['ports']},
       'ShmSize':65536000,'Memory':0,'PidsLimit':0,'Ulimits':[{'Name':'RLIMIT_NPROC','Soft':4194304,'Hard':4194304}],
       'LogConfig':{'Type':'k8s-file'},'Privileged':False,'SecurityOpt':[], 'CapAdd':[], 'CapDrop':[], 'UsernsMode':''}
    return {'Id':r.OLD[service]['id'],'Image':r.releases.SPEC[service]['image'],'Name':r.name(service),
      'Config':{'Cmd':r.OLD[service]['cmd'],'User':'root' if service=='postfix' else '',
                'Entrypoint':None,'Env':['A=1','B=2'],'WorkingDir':'/','Labels':{},'StopSignal':'SIGTERM','StopTimeout':10},
      'HostConfig':h,'State':{'Running':True,'Status':'running','ExitCode':0,'ConmonPid':1},
      'Mounts':[{'Type':'bind','Source':v,'Destination':k,'RW':True} for k,v in r.expected_mounts(service).items()],
      'NetworkSettings':{'Networks':{'ac_network':{'IPAddress':r.OLD[service]['ip'],'GlobalIPv6Address':r.OLD[service]['ip6'],'MacAddress':r.MAC[service]}}}}


class FakePod:
    def __init__(self):
        self.objects={r.OLD[s]['id']:container(s) for s in r.SERVICES}
        self.events=[]
    def inspect(self,key):
        if key in self.objects: return copy.deepcopy(self.objects[key])
        for item in self.objects.values():
            if item['Name']==key: return copy.deepcopy(item)
        raise RuntimeError('Unknown container')
    def __call__(self,*args,**kwargs):
        self.events.append(args)
        stdout='';rc=0
        if args[0]=='rename': self.objects[args[1]]['Name']=args[2]
        elif args[0]=='update': self.objects[args[2]]['HostConfig']['RestartPolicy']['Name']=args[1].split('=')[1]
        elif args[0] in ('kill','start'):
            c=self.objects[args[-1]];running=args[0]=='start'
            c['State'].update(Running=running,Status='running' if running else 'exited',ExitCode=0)
        elif args[:2]==('container','exists'):
            rc=0 if any(c['Name']==args[2] for c in self.objects.values()) else 1
        elif args[0]=='create':
            s=next(s for s in r.SERVICES if r.name(s)==args[args.index('--name')+1])
            c=container(s);c['Id']=('c' if s=='dovecot' else 'd')*64
            c['State'].update(Running=False,Status='created');c['Config']['StopTimeout']=120
            c['Config']['Env'].reverse()  # Podman may reorder environment entries.
            c['HostConfig']['RestartPolicy']['Name']='no'
            label=args[args.index('--label')+1];key,value=label.split('=',1);c['Config']['Labels'][key]=value
            c['Mounts']=[]
            for i,arg in enumerate(args):
                if arg=='-v':
                    src,dst,mode=args[i+1].split(':')
                    c['Mounts'].append({'Type':'bind','Source':src,'Destination':dst,'RW':mode=='rw'})
            self.objects[c['Id']]=c;stdout=c['Id']+'\n'
        else: raise AssertionError('Unimplemented '+repr(args))
        return subprocess.CompletedProcess(args,rc,stdout,'')


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        for key,value in {'STATE':self.root,'PENDING':self.root/'pending.json','ACTIVE':self.root/'active.json',
                          'MARKER':self.root/'marker','LEGACY_BIN':self.root/'bin','PG':self.root/'pg',
                          'LIB':self.root/'lib'}.items():
            p=patch.object(r,key,value);p.start();self.addCleanup(p.stop)
        for directory in (r.LEGACY_BIN,r.PG,r.LIB/'legacy'): directory.mkdir(parents=True)
        for short in ('start','stop'):
            for suffix in ('before','after'):
                shutil.copyfile(ROOT/'legacy'/(short+'.'+suffix),r.LIB/'legacy'/(short+'.'+suffix))
            data=(r.LIB/'legacy'/(short+'.before')).read_bytes()
            (r.LEGACY_BIN/(short+'_ac_containers.sh')).write_bytes(data)
            (r.PG/(short+'.after')).write_bytes(data)
        self.fake=FakePod()
        for key,value in {'pod':self.fake,'inspect':self.fake.inspect,'pg_health':lambda:None,
                          'idle_legacy':lambda:None,'verify_supervised':lambda s,c:None,
                          'pause':lambda s:self.fake.events.append(('pause',s)),
                          'up':lambda s:self.fake('start',r.readjson(r.ACTIVE)[s]['id'])}.items():
            p=patch.object(r,key,value);p.start();self.addCleanup(p.stop)
        def fake_run(args,**kw):
            self.fake.events.append(tuple(args))
            return subprocess.CompletedProcess(args,0,'','')
        p=patch.object(r,'run',fake_run);p.start();self.addCleanup(p.stop)
    def candidate(self,s):
        old=container(s);config=self.root/(s+'-config');data=self.root/'postfix-data'
        args=r.candidate_command(s,old,config,data);args[1:1]=['--label','ac.mail.transaction=test']
        cid=self.fake(*args).stdout.strip()
        return old,self.fake.inspect(cid),config,data,args
    def test_candidates_keep_queue_and_remove_postfix_mail_mount(self):
        for s in r.SERVICES:
            old,c,config,data,args=self.candidate(s)
            r.verify_candidate(s,c,old,config,data)
            self.assertNotIn('--replace',args)
            if s=='postfix':
                self.assertNotIn('/var/mail',[m['Destination'] for m in c['Mounts']])
                self.assertIn(str(r.SPOOL)+':/var/spool:rw',args)
                self.assertEqual(args[args.index('--mac-address')+1],r.MAC['postfix'])
                self.assertNotEqual(r.MAC['postfix'],r.MAC['dovecot'])
    def test_host_list_order_is_not_configuration_drift(self):
        old,c,config,data,_=self.candidate('postfix')
        bindings=old['HostConfig']['PortBindings']['25/tcp']
        bindings.append({'HostIp':'2a0c:b9c0:f:433c::1','HostPort':'25'})
        c['HostConfig']['PortBindings']['25/tcp']=list(reversed(bindings))
        c['HostConfig']['CapAdd']=None
        r.verify_candidate('postfix',c,old,config,data)
    def test_changed_environment_or_image_refused(self):
        old,c,config,data,_=self.candidate('postfix')
        c['Config']['Env'][0]='B=wrong'
        with self.assertRaisesRegex(RuntimeError,'environment'): r.verify_candidate('postfix',c,old,config,data)
        c['Image']='0'*64
        with self.assertRaisesRegex(RuntimeError,'image'): r.verify_candidate('postfix',c,old,config,data)
    def test_legacy_and_postgresql_reference_switch_and_restore(self):
        r.old_scripts();r.set_legacy(True)
        for short in ('start','stop'):
            data=(r.LIB/'legacy'/(short+'.after')).read_bytes()
            self.assertEqual((r.PG/(short+'.after')).read_bytes(),data)
            self.assertEqual((r.LEGACY_BIN/(short+'_ac_containers.sh')).read_bytes(),data)
            self.assertIn(b'/etc/ac/managed/postgresql',data)
            self.assertIn(b'/etc/ac/managed/mail',data)
        r.set_legacy(False);r.old_scripts()
    def test_legacy_unknown_edit_not_overwritten(self):
        target=r.LEGACY_BIN/'start_ac_containers.sh';target.write_text('unrelated edit')
        with self.assertRaisesRegex(RuntimeError,'unrelated'): r.set_legacy(True)
        self.assertEqual(target.read_text(),'unrelated edit')
    def run_migration(self,fail_health=False,fail_verify=False):
        original={s:container(s) for s in r.SERVICES}
        paths={s:self.root/(s+'-source') for s in r.SERVICES}
        def config(s,path,journal):
            dest=journal/(s+'-release');dest.mkdir();return dest
        def backup(record):
            self.assertTrue(all(not self.fake.inspect(r.OLD[s]['id'])['State']['Running'] for s in r.SERVICES))
            self.fake.events.append(('backup',))
        def healthy(active):
            if fail_health: raise RuntimeError('Injected health failure')
        def basic(s,cid): self.assertTrue(self.fake.inspect(cid)['State']['Running'])
        with patch.object(r,'preflight',return_value=original),patch.object(r,'build_config',side_effect=config),\
             patch.object(r,'backup',side_effect=backup),patch.object(r,'healthy_pair',side_effect=healthy),\
             patch.object(r,'basic_health',side_effect=basic):
            if fail_verify:
                with patch.object(r,'verify_candidate',side_effect=RuntimeError('Injected candidate failure')):
                    r.migrate(paths)
            else: r.migrate(paths)
    def test_successful_transaction_preserves_originals(self):
        self.run_migration()
        self.assertFalse(r.PENDING.exists());self.assertTrue(r.MARKER.exists())
        active=r.readjson(r.ACTIVE)
        for s in r.SERVICES:
            self.assertTrue(self.fake.inspect(active[s]['id'])['State']['Running'])
            self.assertFalse(self.fake.inspect(r.OLD[s]['id'])['State']['Running'])
            self.assertIn('-rollback-',self.fake.inspect(r.OLD[s]['id'])['Name'])
        events=self.fake.events
        backup=events.index(('backup',));creates=[i for i,e in enumerate(events) if e[0]=='create']
        self.assertTrue(all(backup<i for i in creates))
        self.assertFalse(any(e[:2]==('systemctl','stop') and 'ac_containers.service' in e for e in events))
    def test_post_start_failure_stops_candidates_before_originals(self):
        with self.assertRaisesRegex(RuntimeError,'Injected health'): self.run_migration(fail_health=True)
        self.assertFalse(r.PENDING.exists());self.assertFalse(r.ACTIVE.exists());r.old_scripts()
        events=self.fake.events
        kills=[i for i,e in enumerate(events) if e[0]=='kill' and e[-1] in ('c'*64,'d'*64)]
        starts=[i for i,e in enumerate(events) if e[0]=='start' and e[-1] in [r.OLD[s]['id'] for s in r.SERVICES]]
        self.assertEqual(len(kills),2);self.assertTrue(max(kills)<min(starts))
        for s in r.SERVICES:
            c=self.fake.inspect(r.OLD[s]['id']);self.assertTrue(c['State']['Running']);self.assertEqual(c['Name'],r.name(s))
    def test_created_but_unstarted_candidate_rolls_back(self):
        with self.assertRaisesRegex(RuntimeError,'Injected candidate'): self.run_migration(fail_verify=True)
        self.assertFalse(r.PENDING.exists());self.assertFalse(r.MARKER.exists())
        self.assertTrue(all(self.fake.inspect(r.OLD[s]['id'])['State']['Running'] for s in r.SERVICES))
    def test_failed_candidate_stop_never_starts_original(self):
        self.run_migration()
        record=r.readjson(next(self.root.glob('switch-*/transaction.json')))
        self.fake.events.clear()
        with patch.object(r,'stop_id',side_effect=RuntimeError('Cannot stop')):
            with self.assertRaisesRegex(RuntimeError,'Cannot stop'): r.rollback(record)
        self.assertTrue(r.PENDING.exists())
        self.assertFalse(any(e[0]=='start' for e in self.fake.events))
    def test_recovery_discovers_candidate_created_before_journal_update(self):
        self.run_migration()
        record=r.readjson(next(self.root.glob('switch-*/transaction.json')))
        record['candidates'].pop('postfix')
        with patch.object(r,'basic_health'):
            r.rollback(record)
        self.assertFalse(r.PENDING.exists())
        self.assertEqual(record['candidates']['postfix'],'d'*64)
        self.assertTrue(all(self.fake.inspect(r.OLD[s]['id'])['State']['Running'] for s in r.SERVICES))
    def test_unknown_candidate_is_not_stopped_or_replaced(self):
        self.run_migration()
        record=r.readjson(next(self.root.glob('switch-*/transaction.json')))
        self.fake.objects['d'*64]['Config']['Labels']['ac.mail.transaction']='other'
        self.fake.events.clear()
        with self.assertRaisesRegex(RuntimeError,'Wrong candidate'): r.rollback(record)
        self.assertFalse(any(e[0] in ('kill','start','rename') for e in self.fake.events))
    def test_pg_health_uses_already_locked_module_without_cli(self):
        source=r.PG.parent/'ac-pg-runtime.py'
        source.write_text("def load_active(): pass\ndef healthy(): pass\ndef script_status(): return [True, True]\n")
        self.fake.events.clear();PG_HEALTH()
        self.assertFalse(self.fake.events)
    def test_shutdown_timeout_never_force_kills(self):
        cid=r.OLD['dovecot']['id'];self.fake.objects[cid]['HostConfig']['RestartPolicy']['Name']='no'
        always=copy.deepcopy(self.fake.objects[cid])
        with patch.object(r,'inspect',return_value=always),patch.object(r.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'no SIGKILL'): r.stop_id(cid)
        self.assertEqual([e for e in self.fake.events if e[0]=='kill'],[('kill','--signal','TERM',cid)])
    def test_changed_active_container_refused(self):
        old,c,config,data,args=self.candidate('dovecot')
        r.putjson(r.ACTIVE,{'dovecot':{'fingerprint':r.fingerprint(c)}})
        r.verify_active('dovecot',c)
        c['Id']='e'*64
        with self.assertRaisesRegex(RuntimeError,'differs'): r.verify_active('dovecot',c)
    def test_no_forced_stop_flags_in_sources(self):
        source=(ROOT/'mail_runtime.py').read_text()
        self.assertNotIn("'--replace'",source)
        self.assertNotIn("'--force'",source)
        self.assertNotIn("'KILL'",source)
    def test_shell_syntax(self):
        for filename in [ROOT/'ac-mailctl',*list((ROOT/'runit').rglob('run')),*list((ROOT/'runit').rglob('finish')),*list((ROOT/'runit').rglob('t'))]:
            subprocess.run(['sh','-n',str(filename)],check=True)
        for filename in (ROOT/'legacy').iterdir(): subprocess.run(['bash','-n',str(filename)],check=True)

if __name__=='__main__': unittest.main()
