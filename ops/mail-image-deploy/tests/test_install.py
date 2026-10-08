import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import nullcontext
from unittest.mock import patch
from test_image_deploy import ROOT,r,c

spec=importlib.util.spec_from_file_location('mail_image_install',ROOT/'install.py')
i=importlib.util.module_from_spec(spec);spec.loader.exec_module(i)

class InstallTests(unittest.TestCase):
    def test_repeated_install_preserves_state_and_does_not_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);state=root/'state';state.mkdir()
            source=root/'source';source.mkdir()
            dest={}
            ref={}
            for name in i.DEST:
                shutil.copyfile(ROOT/name,source/name)
                target=root/('new/'+name if name in ('mail_image.py','ac-mail-image') else 'existing/'+name)
                dest[name]=target
                if name not in ('mail_image.py','ac-mail-image'):
                    target.parent.mkdir(exist_ok=True);target.write_text('# reviewed old source\n')
                    ref[str(target)]=hashlib.sha256(target.read_bytes()).hexdigest()
            (source/'engine-sha256.json').write_text(json.dumps(ref))
            enabled=state/'enabled';enabled.write_text('keep')
            with patch.object(i,'SOURCE',source),patch.object(i,'DEST',dest),patch.object(r,'STATE',state),\
                 patch.object(r,'PENDING',state/'pending'),patch.object(r,'locks',return_value=nullcontext()),\
                 patch.object(c,'check_active',return_value={}),patch.object(r,'readjson',return_value={}),\
                 patch.object(c,'safe_parents'),patch.object(c,'safe'),patch.object(r,'healthy_pair'),\
                 patch.object(c,'ENABLED',enabled),patch.object(i.os,'geteuid',return_value=0),\
                 patch.object(r,'up') as up,patch.object(r,'pause') as pause:
                i.install();i.install()
                up.assert_not_called();pause.assert_not_called()
                self.assertEqual(enabled.read_text(),'keep')
                for name,target in dest.items(): self.assertEqual(target.read_bytes(),(source/name).read_bytes())
                dest['mail_runtime.py'].write_text('unexpected source')
                with self.assertRaisesRegex(RuntimeError,'source differs'):i.install()
                self.assertEqual(dest['mail_runtime.py'].read_text(),'unexpected source')

if __name__=='__main__': unittest.main()
