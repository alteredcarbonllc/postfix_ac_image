import copy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import mail_config as c
r=c.r

class ArchiveTests(unittest.TestCase):
    def archive(self,entries):
        f=tempfile.NamedTemporaryFile(suffix='.tar',delete=False);f.close();p=Path(f.name);self.addCleanup(p.unlink)
        with tarfile.open(p,'w') as t:
            for name,data,typ in entries:
                m=tarfile.TarInfo(name);m.type=typ;m.size=len(data);m.mode=0o644
                t.addfile(m,io.BytesIO(data))
        return p
    def valid(self):return [(n,b'test\n',tarfile.REGTYPE) for n in r.releases.SPEC['dovecot']['files']]
    def test_exact_file_set(self):
        self.assertEqual(set(c.decode_archive(self.archive(self.valid()),'dovecot')),set(r.releases.SPEC['dovecot']['files']))
    def test_missing_file(self):
        with self.assertRaisesRegex(RuntimeError,'Missing'):c.decode_archive(self.archive(self.valid()[:1]),'dovecot')
    def test_duplicate_file(self):
        with self.assertRaisesRegex(RuntimeError,'duplicate'):c.decode_archive(self.archive(self.valid()+self.valid()[:1]),'dovecot')
    def test_traversal_and_absolute_paths(self):
        for path in ('../outside','/etc/shadow','dovecot/../outside','./dovecot/dovecot.conf'):
            with self.subTest(path=path),self.assertRaises(RuntimeError):
                c.decode_archive(self.archive([(path,b'x',tarfile.REGTYPE)]),'dovecot')
    def test_links_and_unknown_files(self):
        for typ in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.FIFOTYPE):
            with self.subTest(typ=typ),self.assertRaises(RuntimeError):
                c.decode_archive(self.archive([('dovecot/dovecot.conf',b'',typ)]),'dovecot')
        with self.assertRaises(RuntimeError):c.decode_archive(self.archive(self.valid()+[('exploit.py',b'print(1)',tarfile.REGTYPE)]),'dovecot')
    def test_oversized_file(self):
        items=self.valid();items[0]=(items[0][0],b'x'*262145,tarfile.REGTYPE)
        with self.assertRaises(RuntimeError):c.decode_archive(self.archive(items),'dovecot')

class ImportTests(unittest.TestCase):
    def setUp(self):
        previous=os.umask(0o077);self.addCleanup(os.umask,previous)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.revision='a'*40
        for key,value in {'STATE':self.root,'INBOX':self.root/'inbox','RELEASES':self.root/'releases','UID':os.getuid()}.items():
            p=patch.object(c,key,value);p.start();self.addCleanup(p.stop)
        (c.INBOX/'dovecot').mkdir(parents=True,mode=0o700)
        def safe(path,directory=False):
            st=path.lstat()
            c.need((stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)) and st.st_uid==os.getuid() and not st.st_mode&0o022,'Unsafe fixture')
            return st
        p=patch.object(c,'safe',safe);p.start();self.addCleanup(p.stop)
        p=patch.object(c,'safe_parents');p.start();self.addCleanup(p.stop)
        p=patch.object(r.releases,'read_secret',return_value={'connect':'host=127.0.0.1 password=example'});p.start();self.addCleanup(p.stop)
        def validate(kind,stage):
            r.atomic(stage/'validation.stdout',b'');r.atomic(stage/'validation.stderr',b'')
        p=patch.object(r.releases,'validate',side_effect=validate);p.start();self.addCleanup(p.stop)
    def source(self,value=b'protocols = imap\n'):
        path=c.INBOX/'dovecot'/(self.revision+'.tar')
        with tarfile.open(path,'w') as t:
            for name,data in [('dovecot/dovecot.conf',value),('templates/dovecot-sql.conf.ext.in',b'driver = pgsql\nconnect = @SQL_CONNECT@\n')]:
                m=tarfile.TarInfo(name);m.mode=0o644;m.size=len(data);t.addfile(m,io.BytesIO(data))
        return path
    def test_import_and_repeat_are_immutable(self):
        self.source();first=c.prepare('dovecot',self.revision)
        self.assertEqual(c.prepare('dovecot',self.revision),first)
        c.verify_release(first,'dovecot')
    def test_same_revision_different_source_is_refused(self):
        self.source();c.prepare('dovecot',self.revision);self.source(b'changed')
        with self.assertRaisesRegex(RuntimeError,'different source'):c.prepare('dovecot',self.revision)
    def test_secret_rotation_creates_another_private_release(self):
        self.source();first=c.prepare('dovecot',self.revision)
        with patch.object(r.releases,'read_secret',return_value={'connect':'host=127.0.0.1 password=rotated'}):
            second=c.prepare('dovecot',self.revision)
        self.assertNotEqual(first,second);c.verify_release(first,'dovecot');c.verify_release(second,'dovecot')
    def test_inbox_symlink_is_refused(self):
        path=self.source();other=path.with_suffix('.original');path.rename(other);path.symlink_to(other)
        with self.assertRaises(OSError):c.prepare('dovecot',self.revision)
    def test_release_drift_is_refused(self):
        self.source();release=c.prepare('dovecot',self.revision)
        (release/'config/dovecot.conf').write_text('changed')
        with self.assertRaisesRegex(RuntimeError,'drift'):c.verify_release(release,'dovecot')

class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        for module,values in [(c,{'STATE':self.root,'CURRENT':self.root/'current.json','PENDING':self.root/'pending-config.json'}),
                              (r,{'STATE':self.root,'ACTIVE':self.root/'active.json','PENDING':self.root/'pending-switch.json','PGLOCK':self.root/'pg.lock','PGPENDING':self.root/'pg.pending'})]:
            for key,value in values.items():
                p=patch.object(module,key,value);p.start();self.addCleanup(p.stop)
        def fixture_safe(path,directory=False):
            st=path.lstat()
            c.need((stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)) and st.st_uid==os.getuid() and not st.st_mode&0o022,'Unsafe fixture')
            return st
        for key,value in {'safe':fixture_safe,'safe_parents':lambda p:None}.items():
            p=patch.object(c,key,value);p.start();self.addCleanup(p.stop)
        self.events=[];self.running={k:True for k in r.SERVICES}
        self.active={k:{'id':k,'fingerprint':{},'release':'bootstrap'} for k in r.SERVICES}
        r.putjson(r.ACTIVE,self.active)
        self.containers={};state={}
        for kind in r.SERVICES:
            config=self.root/kind/'config';config.mkdir(parents=True)
            secrets=self.root/kind/'secrets';secrets.mkdir()
            (config/'pgsql').mkdir()
            self.containers[kind]={'Id':kind,'Image':r.releases.SPEC[kind]['image'],
                'Mounts':[{'Destination':'/etc/'+kind,'Source':str(config)},{'Destination':'/run/secrets/dovecot','Source':str(secrets)}]}
            names=['config/dovecot.conf','secrets/dovecot-sql.conf.ext'] if kind=='dovecot' else ['config/main.cf','config/master.cf']+['secrets/'+n+'.pgsql' for n in r.releases.NAMES]
            mapping={}
            for name in names:
                path=(config/name.split('/')[1]) if name.startswith('config/') else ((secrets if kind=='dovecot' else config/'pgsql')/name.split('/')[1])
                path.write_bytes(b'old '+name.encode());path.chmod(0o600);mapping[name]=path
            state[kind]={'release':'bootstrap','revision':'a'*40,'files':{k:c.file_record(v) for k,v in mapping.items()}}
            down=self.root/'services'/kind;down.mkdir(parents=True)
        r.putjson(c.CURRENT,state);self.old=state
        def inspect(cid):
            result=copy.deepcopy(self.containers[cid]);result['State']={'Running':self.running[cid]};return result
        def pause(kind):self.events.append(('pause',kind));self.running[kind]=False
        def stop(cid):self.events.append(('stop',cid));self.running[cid]=False
        def up(kind):self.events.append(('up',kind));self.running[kind]=True
        for key,value in {'inspect':inspect,'verify_active':lambda k,v:None,'pause':pause,'stop_id':stop,'up':up,
                          'wait_health':lambda k,i:None,'healthy_pair':lambda a:None,'service_dir':lambda k:self.root/'services'/k}.items():
            p=patch.object(r,key,value);p.start();self.addCleanup(p.stop)
        self.release=self.root/'candidate';self.release.mkdir()
        self.manifest={'revision':'b'*40,'rendered':{}}
        for filename,meta in self.old['dovecot']['files'].items():
            path=self.release/filename;path.parent.mkdir(exist_ok=True);path.write_bytes(b'new '+filename.encode())
            self.manifest['rendered'][filename]=c.sha(path.read_bytes())
        p=patch.object(c,'verify_release',return_value=self.manifest);p.start();self.addCleanup(p.stop)
        original_write=c.write_file
        def guarded_write(path,data,metadata):
            self.assertFalse(any(self.running.values()),'Cannot write while either mail service runs')
            self.events.append(('write',data));original_write(path,data,metadata)
        p=patch.object(c,'write_file',guarded_write);p.start();self.addCleanup(p.stop)
    def test_success_updates_hashes_and_preserves_container_ids(self):
        c.deploy('dovecot',self.release)
        self.assertFalse(c.PENDING.exists());self.assertTrue(all(self.running.values()))
        state=r.readjson(c.CURRENT)
        self.assertEqual(state['dovecot']['revision'],'b'*40);self.assertEqual(state['postfix'],self.old['postfix'])
        self.assertEqual(r.readjson(r.ACTIVE),self.active)
        for entry in state.values():c.check_files(entry)
        self.assertEqual([e[1] for e in self.events if e[0]=='stop'],['postfix','dovecot'])
        self.assertEqual([e[1] for e in self.events if e[0]=='up'],['dovecot','postfix'])
    def test_identical_content_is_noop(self):
        for filename,meta in self.old['dovecot']['files'].items():
            self.manifest['rendered'][filename]=meta['sha256'];(self.release/filename).write_bytes(Path(meta['path']).read_bytes())
        c.deploy('dovecot',self.release)
        self.assertFalse(self.events);self.assertEqual(r.readjson(c.CURRENT)['dovecot']['revision'],'b'*40)
    def test_configuration_drift_refused_before_stop(self):
        Path(self.old['dovecot']['files']['config/dovecot.conf']['path']).write_text('manual change')
        with self.assertRaisesRegex(RuntimeError,'drift'):c.deploy('dovecot',self.release)
        self.assertFalse(self.events)
    def test_post_start_failure_restores_files(self):
        with patch.object(r,'healthy_pair',side_effect=[None,RuntimeError('bad candidate'),None]):
            with self.assertRaisesRegex(RuntimeError,'bad candidate'):c.deploy('dovecot',self.release)
        self.assertFalse(c.PENDING.exists());self.assertEqual(r.readjson(c.CURRENT),self.old)
        for entry in self.old.values():c.check_files(entry)
        self.assertTrue(all(self.running.values()))
    def test_failed_rollback_stop_retains_pending_and_no_old_write(self):
        calls=0
        original=c.stopped
        def stopping(active):
            nonlocal calls
            calls+=1
            if calls==2:raise RuntimeError('cannot stop')
            return original(active)
        with patch.object(c,'stopped',side_effect=stopping),patch.object(r,'healthy_pair',side_effect=[None,RuntimeError('bad candidate')]):
            with self.assertRaisesRegex(RuntimeError,'bad candidate'):c.deploy('dovecot',self.release)
        self.assertEqual(r.readjson(c.PENDING)['phase'],'rollback_failed')
        self.assertFalse(any(e[0]=='write' and e[1].startswith(b'old ') for e in self.events))
    def test_recover_after_partial_file_replacement(self):
        journal=self.root/'journal';journal.mkdir()
        for filename,meta in self.old['dovecot']['files'].items():r.atomic(journal/'old'/filename,Path(meta['path']).read_bytes())
        record={'kind':'dovecot','journal':str(journal),'old':self.old,'active':self.active}
        path=Path(self.old['dovecot']['files']['config/dovecot.conf']['path']);path.write_text('partial update')
        c.rollback(record)
        self.assertFalse(c.PENDING.exists())
        for entry in self.old.values():c.check_files(entry)
    def test_runtime_interlock_allows_only_config_recovery_lock(self):
        c.PENDING.write_text('{}')
        with self.assertRaisesRegex(RuntimeError,'Pending mail configuration'):
            with r.locks():pass
        with r.locks(allow_config_pending=True):pass
    def test_invalid_rollback_snapshot_never_starts_pair(self):
        journal=self.root/'journal';journal.mkdir()
        r.atomic(journal/'old/config/dovecot.conf',b'corrupt')
        record={'kind':'dovecot','journal':str(journal),'old':self.old,'active':self.active}
        with self.assertRaisesRegex(RuntimeError,'snapshot drift'):c.rollback(record)
        self.assertFalse(any(e[0]=='up' for e in self.events));self.assertTrue(c.PENDING.exists())

if __name__=='__main__':unittest.main()
