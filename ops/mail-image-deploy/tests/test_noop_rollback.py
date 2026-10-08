import copy
import unittest
from unittest.mock import patch
from test_image_deploy import m,c,r

class NoopRollbackTests(unittest.TestCase):
    def record(self):
        state={k:{'release':'initial','revision':'a'*40,'files':{
            'config':{'path':'/new/'+k,'sha256':'a'*64,'uid':0,'gid':0,'mode':384}
        }} for k in r.SERVICES}
        old=copy.deepcopy(state)
        for k in r.SERVICES: old[k]['files']['config']['path']='/old/'+k
        return {'config':old,'new_config':state}

    def test_noop_keeps_latest_metadata_and_restores_old_paths(self):
        record=self.record();current=copy.deepcopy(record['new_config'])
        current['dovecot'].update(release='latest',revision='b'*40)
        with patch.object(c,'check_files') as check:
            result=m.rollback_config_state(record,current)
        self.assertEqual(check.call_count,2)
        self.assertEqual(result['dovecot']['release'],'latest')
        self.assertEqual(result['dovecot']['revision'],'b'*40)
        self.assertEqual(result['dovecot']['files']['config']['path'],'/old/dovecot')
        self.assertEqual(record['config']['dovecot']['release'],'initial')

    def test_changed_content_path_or_mode_refused(self):
        for key,value in [('sha256','b'*64),('path','/other'),('mode',420),('uid',100),('gid',102)]:
            record=self.record();current=copy.deepcopy(record['new_config'])
            current['postfix']['files']['config'][key]=value
            with self.subTest(key=key),patch.object(c,'check_files'),self.assertRaises(RuntimeError):
                m.rollback_config_state(record,current)

    def test_filesystem_drift_refused(self):
        record=self.record()
        with patch.object(c,'check_files',side_effect=RuntimeError('drift')),self.assertRaisesRegex(RuntimeError,'drift'):
            m.rollback_config_state(record,record['new_config'])
