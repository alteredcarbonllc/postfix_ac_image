import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'mail_release.py'
spec = importlib.util.spec_from_file_location('mail_release', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def test_substitution_literal_secret(self):
        value = "host=db password='@SQL_CONNECT@ $(touch /tmp/never) $HOME'"
        self.assertEqual(m.substitute(b'connect = @SQL_CONNECT@\n', {'SQL_CONNECT': value}),
                         ('connect = '+value+'\n').encode())

    def test_duplicate_unknown_missing_markers(self):
        for text in (b'@X@ @X@', b'@Y@', b'no marker'):
            with self.assertRaises(m.Failure): m.substitute(text, {'X': 'secret'})

    def test_multiline_secret_refused(self):
        for value in ('a\nb', 'a\rb', 'a\0b', '', None):
            with self.assertRaises(m.Failure): m.substitute(b'@X@', {'X': value})

    def test_postfix_per_map_credentials(self):
        files = {'postfix/main.cf': b'main', 'postfix/master.cf': b'master'}
        secret = {'maps': {}}
        for name in m.NAMES:
            files['templates/pgsql/'+name+'.pgsql.in'] = b'@SQL_HOSTS@ @SQL_DATABASE@ @SQL_USER@ @SQL_PASSWORD@'
            secret['maps'][name] = dict(hosts='db', dbname='mail', user=name, password='p-'+name)
        output = m.render('postfix', files, secret)
        for name in m.NAMES:
            self.assertEqual(output['secrets/'+name+'.pgsql'], ('db mail '+name+' p-'+name).encode())

    def test_drift_extra_and_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'a').write_bytes(b'good')
            expected = {'a': m.digest(b'good')}
            m.check_tree(root, expected)
            (root/'a').write_bytes(b'bad')
            with self.assertRaises(m.Failure): m.check_tree(root, expected)
            (root/'a').write_bytes(b'good'); (root/'extra').write_text('x')
            with self.assertRaises(m.Failure): m.check_tree(root, expected)
            (root/'extra').unlink(); (root/'a').unlink(); (root/'a').symlink_to('/etc/passwd')
            with self.assertRaises(m.Failure): m.check_tree(root, expected)

    def test_secret_rotation_changes_manifest(self):
        a = m.manifest_for('dovecot', 'a'*40, {'x': b'template'}, {'s': b'password1'})
        b = m.manifest_for('dovecot', 'a'*40, {'x': b'template'}, {'s': b'password2'})
        self.assertNotEqual(a, b)
        self.assertNotIn('password1', json.dumps(a))

    def make_repo(self, root):
        def g(*args):
            return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL)
        g('init', '-b', 'main')
        for name in m.SPEC['dovecot']['files']:
            p = root/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text('fixture\n')
        g('add', '.')
        g('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'fixture')
        return g, g('rev-parse', 'HEAD').decode().strip()

    def test_snapshot_clean_dirty_untracked(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); g, sha = self.make_repo(root)
            with patch.dict(m.SPEC['dovecot'], revision=sha):
                self.assertEqual(m.snapshot(root,'dovecot')[0], sha)
                (root/'untracked').write_text('x')
                with self.assertRaises(m.Failure): m.snapshot(root,'dovecot')
                (root/'untracked').unlink(); (root/'dovecot/dovecot.conf').write_text('drift')
                with self.assertRaises(m.Failure): m.snapshot(root,'dovecot')

    def test_snapshot_committed_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); g, sha = self.make_repo(root)
            p=root/'dovecot/dovecot.conf'; p.unlink(); p.symlink_to('/etc/passwd')
            g('add','.'); g('-c','user.name=Test','-c','user.email=test@example.invalid','commit','-m','link')
            sha=g('rev-parse','HEAD').decode().strip()
            with patch.dict(m.SPEC['dovecot'],revision=sha):
                with self.assertRaises(m.Failure): m.snapshot(root,'dovecot')

    def test_prepare_failure_not_published_and_secret_not_printed(self):
        with tempfile.TemporaryDirectory() as td:
            source={'dovecot/dovecot.conf': b'conf', 'templates/dovecot-sql.conf.ext.in': b'@SQL_CONNECT@'}
            with patch.object(m,'STATE',Path(td)), patch.object(m,'snapshot',return_value=('a'*40,source)), \
                 patch.object(m,'read_secret',return_value={'connect':'TOPSECRET'}), \
                 patch.object(m,'validate',side_effect=m.Failure('Validation failed')):
                with self.assertRaises(m.Failure): m.prepare('dovecot','unused','unused')
            entries=list((Path(td)/'releases/dovecot').iterdir())
            self.assertEqual(len(entries),1)
            self.assertTrue(entries[0].name.startswith('.prepare-'))
            self.assertFalse((entries[0]/'VALIDATED').exists())
            self.assertNotIn('TOPSECRET', (entries[0]/'manifest.json').read_text())

    def test_prepare_idempotent_and_tamper_refused(self):
        with tempfile.TemporaryDirectory() as td:
            source={'dovecot/dovecot.conf': b'conf', 'templates/dovecot-sql.conf.ext.in': b'@SQL_CONNECT@'}
            def validate(kind, root):
                m.save(root/'validation.stdout', b'ok')
                m.save(root/'validation.stderr', b'')
            original = Path.lstat
            def root_owned(path, *args, **kwargs):
                values = list(original(path, *args, **kwargs))
                values[4] = 0
                return os.stat_result(values)
            with patch.object(m,'STATE',Path(td)), patch.object(m,'snapshot',return_value=('a'*40,source)), \
                 patch.dict(m.SPEC['dovecot'], revision='a'*40), \
                 patch.object(m,'read_secret',return_value={'connect':'secret'}), \
                 patch.object(m,'validate',side_effect=validate) as validator, \
                 patch.object(Path,'lstat',root_owned):
                first = m.prepare('dovecot','unused','unused')
                second = m.prepare('dovecot','unused','unused')
                self.assertEqual(first, second)
                self.assertEqual(validator.call_count, 1)
                (first/'config/dovecot.conf').write_bytes(b'changed')
                with self.assertRaises(m.Failure): m.prepare('dovecot','unused','unused')

    def test_validator_never_starts_production(self):
        with tempfile.TemporaryDirectory() as td:
            for kind in m.SPEC:
                root=Path(td)/kind; root.mkdir()
                calls=[]
                def run(argv, **kwargs):
                    calls.append(argv)
                    return subprocess.CompletedProcess(argv, 0, b'ok', b'')
                with patch.object(m,'command',return_value=b''), patch.object(m.subprocess,'run',side_effect=run):
                    m.validate(kind,root)
                argv=calls[0]
                self.assertIn('--network=none',argv)
                self.assertIn('--pull=never',argv)
                self.assertNotIn('--replace',argv)
                self.assertNotIn('-p',argv)
                self.assertNotIn('start-fg', ' '.join(argv))
                self.assertNotIn('systemctl', ' '.join(argv))

if __name__ == '__main__': unittest.main()
