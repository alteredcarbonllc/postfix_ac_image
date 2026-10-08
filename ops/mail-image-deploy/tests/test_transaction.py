import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from test_image_deploy import m,r,c,container

class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.old={k:container(k,'old-'+k) for k in r.SERVICES}
        self.active={k:{'id':v['Id'],'fingerprint':r.fingerprint(v),'release':'oldrelease'} for k,v in self.old.items()}
        self.config={k:{'revision':'a'*40,'files':{}} for k in r.SERVICES}
        self.images={k:'a'*64 for k in r.SERVICES}
        self.db={v['Id']:copy.deepcopy(v) for v in self.old.values()}
        self.events=[]
        self.patches=[]
        self.p(m,'STATE',self.root);self.p(m,'PENDING',self.root/'pending');self.p(m,'LAST',self.root/'last')
        self.p(r,'ACTIVE',self.root/'active');self.p(c,'CURRENT',self.root/'config')
        self.p(r,'inspect',self.inspect);self.p(r,'pod',self.pod)
        self.p(m,'preflight',lambda report:(self.active,self.config,self.old,self.images))
        self.p(m,'config_tree',lambda *args:{})
        self.p(m,'cold_backup',lambda record:self.events.append('backup'))
        self.p(r,'pause',lambda kind:self.events.append('pause:'+kind))
        self.p(r,'stop_id',self.stop)
        self.p(r,'up',lambda kind:self.events.append('up:'+kind))
        self.p(r,'wait_health',lambda *args:None);self.p(r,'verify_active',lambda *args:None)
        self.p(r,'verify_supervised',lambda *args:None);self.p(r,'pg_health',lambda:None)
        self.p(r,'healthy_pair',lambda active:self.events.append('health'))
        self.p(c,'targets',lambda *args:{});self.p(c,'check_files',lambda entry:None)
        self.p(m.signal,'signal',lambda *args:None)
        self.addCleanup(self.restore)
    def p(self,obj,key,value):
        q=patch.object(obj,key,value);q.start();self.patches.append(q)
    def restore(self):
        for p in reversed(self.patches): p.stop()
    def inspect(self,cid):
        if cid in self.db: return copy.deepcopy(self.db[cid])
        for info in self.db.values():
            if info['Name']==cid: return copy.deepcopy(info)
        raise RuntimeError('missing '+cid)
    def pod(self,*args,**kwargs):
        if args[0]=='rename':
            self.db[args[1]]['Name']=args[2];self.events.append('rename:'+args[1])
            return Mock(stdout='',returncode=0)
        if args[:2]==('container','exists'):
            return Mock(returncode=0 if any(v['Name']==args[2] for v in self.db.values()) else 1)
        if args[0]=='create':
            kind='dovecot' if args[-2:]==('dovecot','-F') else 'postfix'
            cid='new-'+kind;v=copy.deepcopy(self.old[kind]);v['Id']=cid
            v['Image']=self.images[kind];v['Config']['User']='root'
            token=args[args.index('--label')+1].split('=',1)[1]
            v['Config']['Labels']['ac.mail.image-transaction']=token
            self.db[cid]=v;self.events.append('create:'+kind)
            return Mock(stdout=cid,returncode=0)
        raise AssertionError(args)
    def stop(self,cid,clean=True):
        self.events.append('stop:'+cid);self.db[cid]['State']['Running']=False
    def test_success_keeps_originals_and_updates_manifests(self):
        m.deploy(self.root)
        self.assertFalse(m.PENDING.exists())
        result=json.loads(r.ACTIVE.read_text())
        self.assertEqual(result['postfix']['id'],'new-postfix')
        self.assertIn('-rollback-',self.db['old-postfix']['Name'])
        self.assertLess(self.events.index('backup'),self.events.index('create:dovecot'))
        self.assertEqual(json.loads(c.CURRENT.read_text()),self.config)
    def test_failed_health_rolls_back_both_before_starting_old(self):
        count=0
        def health(active):
            if active['postfix']['id'].startswith('new'): raise RuntimeError('health failure')
        self.p(r,'healthy_pair',health)
        with self.assertRaisesRegex(RuntimeError,'health failure'): m.deploy(self.root)
        self.assertFalse(m.PENDING.exists())
        self.assertEqual(json.loads(r.ACTIVE.read_text())['postfix']['id'],'old-postfix')
        lastup=len(self.events)-1-self.events[::-1].index('up:dovecot')
        self.assertLess(self.events.index('stop:new-postfix'),lastup)
        self.assertLess(self.events.index('stop:new-dovecot'),lastup)
    def test_created_unrecorded_candidate_discovered_on_failure(self):
        real=self.pod
        def pod(*args,**kwargs):
            result=real(*args,**kwargs)
            if args[0]=='create': raise RuntimeError('lost create response')
            return result
        self.p(r,'pod',pod)
        with self.assertRaisesRegex(RuntimeError,'lost create response'): m.deploy(self.root)
        self.assertIn('stop:new-dovecot',self.events)
        self.assertEqual(self.db['old-dovecot']['Name'],r.name('dovecot'))
        self.assertFalse(m.PENDING.exists())
    def test_failed_stop_retains_journal_and_never_restarts_old(self):
        def stop(cid,clean=True):
            if cid.startswith('new'): raise RuntimeError('cannot stop')
            self.stop(cid,clean)
        self.p(r,'stop_id',stop)
        self.p(r,'healthy_pair',Mock(side_effect=RuntimeError('health failure')))
        with self.assertRaisesRegex(RuntimeError,'health failure'): m.deploy(self.root)
        self.assertTrue(m.PENDING.exists())
        self.assertEqual(json.loads(m.PENDING.read_text())['phase'],'rollback_failed')
        self.assertIn('-rollback-',self.db['old-dovecot']['Name'])
        self.assertEqual(self.events.count('up:dovecot'),1)
    def test_configuration_changed_before_stop_refused(self):
        self.p(m,'preflight',Mock(side_effect=RuntimeError('drift')))
        with self.assertRaisesRegex(RuntimeError,'drift'): m.deploy(self.root)
        self.assertEqual(self.events,[])

if __name__=='__main__': unittest.main()
