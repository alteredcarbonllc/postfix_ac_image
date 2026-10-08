import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    if name in sys.modules: return sys.modules[name]
    spec=importlib.util.spec_from_file_location(name,ROOT/(name+'.py'))
    mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod;spec.loader.exec_module(mod)
    return mod
release=load('mail_release');r=load('mail_runtime');c=load('mail_config');m=load('mail_image')

def container(kind,cid='old'):
    return {'Id':cid,'Image':release.SPEC[kind]['image'],'Name':r.name(kind),
        'Config':{'Cmd':r.OLD[kind]['cmd'],'Env':['PATH=/usr/sbin:/usr/bin:/bin'],
                  'User':'','WorkingDir':'/','Entrypoint':None,'Hostname':'mail',
                  'StopSignal':'SIGTERM','StopTimeout':120,'Labels':{}},
        'HostConfig':{'ShmSize':65536,'Memory':0,'PidsLimit':2048,'LogConfig':{'Type':'k8s-file','Config':{}},
                      'PortBindings':{'25/tcp':[{'HostIp':'93.115.20.205','HostPort':'25'}]},
                      'RestartPolicy':{'Name':'no'}},
        'State':{'Running':False},
        'Mounts':[{'Type':'bind','Source':'/var/lib/ac-mail/old/'+kind,
                   'Destination':'/etc/'+kind,'RW':kind=='postfix'},
                  {'Type':'bind','Source':'/data/'+kind,'Destination':'/var/mail' if kind=='dovecot' else '/var/spool','RW':True}]}

class Tests(unittest.TestCase):
    def test_create_immutable_image_and_preserve_mounts(self):
        old=container('postfix')
        args=m.create_args('postfix',old,'a'*64,{'/etc/postfix':'/var/lib/ac-mail/new'},'tx')
        self.assertEqual(args[-3:],['a'*64,'postfix','start-fg'])
        self.assertIn('type=bind,source=/data/postfix,destination=/var/spool,ro=false',args)
        self.assertIn('type=bind,source=/var/lib/ac-mail/new,destination=/etc/postfix,ro=false',args)
        self.assertNotIn('--replace',args)
        self.assertIn('--restart=no',args)

    def test_unsupported_security_refused(self):
        old=container('postfix');old['HostConfig']['Privileged']=True
        with self.assertRaises(RuntimeError): m.create_args('postfix',old,'a'*64,{},'tx')

    def test_verify_candidate_detects_environment_and_data_drift(self):
        old=container('postfix');new=copy.deepcopy(old)
        new.update(Id='new',Image='a'*64);new['Config']['User']='root'
        new['Config']['Labels']['ac.mail.image-transaction']='tx'
        record={'old':{'postfix':old},'images':{'postfix':'a'*64},'mounts':{'postfix':{}},'token':'tx'}
        m.verify_new('postfix',new,record)
        new['Config']['Env'].append('EXTRA=1')
        with self.assertRaises(RuntimeError): m.verify_new('postfix',new,record)
        new['Config']['Env'].pop();new['Mounts'][1]['Source']='/other'
        with self.assertRaises(RuntimeError): m.verify_new('postfix',new,record)

    def test_receipt_wrong_id_refused(self):
        with patch.object(m,'protected'),patch.object(r,'readjson',return_value={}):
            with self.assertRaises(RuntimeError): m.candidate_image('dovecot')

    def test_discover_created_before_journal(self):
        info=container('postfix','new');info['Image']='a'*64
        info['Config']['Labels']={'ac.mail.image-transaction':'tx'}
        record={'token':'tx','old':{'postfix':container('postfix')},'images':{'postfix':'a'*64},'candidates':{}}
        with patch.object(r,'pod',return_value=Mock(returncode=0)),patch.object(r,'inspect',return_value=info),patch.object(m,'phase'):
            self.assertEqual(m.discover(record,'postfix'),'new')
        record['candidates']={};info['Config']['Labels']={}
        with patch.object(r,'pod',return_value=Mock(returncode=0)),patch.object(r,'inspect',return_value=info),patch.object(m,'phase'):
            with self.assertRaises(RuntimeError): m.discover(record,'postfix')

    def test_failed_candidate_stop_never_starts_originals(self):
        info=container('postfix','new');info['Image']='a'*64
        info['Config']['Labels']={'ac.mail.image-transaction':'tx'}
        record={'token':'tx','images':{'postfix':'a'*64}}
        with patch.object(m,'phase'),patch.object(r,'pause'),patch.object(m,'discover',return_value='new'),\
             patch.object(r,'inspect',return_value=info),patch.object(r,'stop_id',side_effect=RuntimeError('timeout')),\
             patch.object(r,'up') as up,patch.object(r,'putjson') as write:
            with self.assertRaises(RuntimeError): m.rollback(record)
            up.assert_not_called();write.assert_not_called()

    def test_config_ci_accepts_root_recorded_new_image(self):
        active={k:{'id':k} for k in r.SERVICES}
        with tempfile.TemporaryDirectory() as tmp,patch.object(r,'PENDING',Path(tmp)/'pending'),\
             patch.object(r,'readjson',return_value=active),patch.object(r,'verify_active') as verify,\
             patch.object(r,'inspect',return_value={'State':{'Running':True},'Image':'a'*64}),\
             patch.object(r,'service_dir',return_value=Path(tmp)):
            self.assertEqual(c.check_active(),active)
            self.assertEqual(verify.call_count,2)

    def test_runtime_interlock_refuses_pending_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'pending-image.json').write_text('{}')
            with patch.object(r,'STATE',root),patch.object(r,'PGLOCK',root/'pg.lock'),patch.object(r,'PGPENDING',root/'pg.pending'):
                with self.assertRaises(RuntimeError):
                    with r.locks(): pass
                with r.locks(allow_image_pending=True): pass

    def test_config_validation_uses_explicit_candidate_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'config').mkdir();(root/'secrets').mkdir()
            with patch.object(release,'command'),patch.object(release.subprocess,'run',return_value=Mock(stdout=b'',stderr=b'',returncode=0)) as run:
                release.validate('dovecot',root,image='a'*64)
                self.assertIn('a'*64,run.call_args.args[0])

if __name__=='__main__': unittest.main()
