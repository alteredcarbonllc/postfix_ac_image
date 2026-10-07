import ast
import copy
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest

BASE=Path(__file__).resolve().parents[1]
KIND=BASE.parents[1].name.removesuffix('_ac_image')
REV='a'*40
def load(name,path):
    loader=importlib.machinery.SourceFileLoader(name,str(path))
    spec=importlib.util.spec_from_loader(name,loader)
    m=importlib.util.module_from_spec(spec);loader.exec_module(m)
    return m
imp=load('mail_import',BASE/('ac-'+KIND+'-import'))
test=load('mail_test',BASE/'test-image.py')
def cfg():
    return {'User':'root','Entrypoint':None,'Cmd':['dovecot','-F'] if KIND=='dovecot' else ['postfix','start-fg'],
            'StopSignal':'SIGTERM','Labels':{'org.opencontainers.image.revision':REV}}
def archive(tag=None,special=False,duplicate=False,config=None,extra=None):
    buff=io.BytesIO()
    manifest=[{'Config':'config.json','RepoTags':[tag or 'localhost/'+KIND+'-ac:'+REV],'Layers':['layer.tar']}]
    config=config or {'architecture':'amd64','os':'linux','config':cfg()}
    with tarfile.open(fileobj=buff,mode='w') as tar:
        for name,data in [('manifest.json',json.dumps(manifest).encode()),('config.json',json.dumps(config).encode()),('layer.tar',b'layer')]:
            member=tarfile.TarInfo(name);member.size=len(data)
            if special and name=='layer.tar':
                member.type=tarfile.SYMTYPE;member.linkname='/etc/passwd';member.size=0
            tar.addfile(member,io.BytesIO(data) if member.isfile() else None)
        if duplicate: tar.addfile(tarfile.TarInfo('config.json'),io.BytesIO())
        if extra: tar.addfile(tarfile.TarInfo(extra),io.BytesIO())
    buff.seek(0)
    return tarfile.open(fileobj=buff,mode='r:')
class ImportTests(unittest.TestCase):
    def test_valid(self):
        with archive() as a: ref,ident,selected=imp.manifest_info(a,REV)
        self.assertEqual(ref,'localhost/'+KIND+'-ac:'+REV)
        self.assertEqual(len(ident),71)
        self.assertEqual(len(selected),3)
    def test_wrong_tag(self):
        with archive(tag='localhost/other:'+REV) as a:
            with self.assertRaises(ValueError): imp.manifest_info(a,REV)
    def test_links_duplicate_and_traversal(self):
        for kw in ({'special':True},{'duplicate':True},{'extra':'../escape'},{'extra':'/absolute'}):
            with archive(**kw) as a:
                with self.assertRaises(ValueError): imp.manifest_info(a,REV)
    def test_wrong_metadata(self):
        for key,value in [('User','postgres'),('Entrypoint',['sh']),('Volumes',{'/var/mail':{}}),
                          ('Cmd',['sleep','infinity']),('StopSignal','SIGKILL'),
                          ('Labels',{'org.opencontainers.image.revision':'b'*40})]:
            config={'architecture':'amd64','os':'linux','config':cfg()}
            config['config'][key]=value
            with archive(config=config) as a:
                with self.assertRaises(ValueError): imp.manifest_info(a,REV)
    def test_separate_inbox_and_receipt(self):
        self.assertEqual(imp.INBOX,'/var/spool/ac-mail-images/'+KIND+'/inbox')
        self.assertEqual(imp.STATE,'/var/lib/ac-mail/image-imports/'+KIND)
class ImageTests(unittest.TestCase):
    def test_valid(self):
        test.metadata({'Architecture':'amd64','Os':'linux','Config':cfg()},REV)
    def test_wrong_platform(self):
        with self.assertRaises(RuntimeError):
            test.metadata({'Architecture':'arm64','Os':'linux','Config':cfg()},REV)
    def test_wrong_revision(self):
        with self.assertRaises(RuntimeError):
            test.metadata({'Architecture':'amd64','Os':'linux','Config':cfg()},'b'*40)
    def test_fixture_is_network_none_without_host_mounts(self):
        source=(BASE/'test-image.py').read_text()
        self.assertIn("'--network=none'",source)
        self.assertIn("'--network=container:'+fx",source)
        self.assertNotIn('/var/volumes',source)
        self.assertNotIn('/etc/ac/secrets',source)
        self.assertNotIn("'--privileged'",source)
    def test_sources_parse(self):
        for path in BASE.rglob('*.py'):
            ast.parse(path.read_text(),filename=str(path))
        ast.parse((BASE/('ac-'+KIND+'-import')).read_text())
if __name__=='__main__': unittest.main()
