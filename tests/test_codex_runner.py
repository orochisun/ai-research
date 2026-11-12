import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import codex_runner

class RunnerTests(unittest.TestCase):
    def test_snapshot_changed_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'a.py').write_text('changed')
            with patch.object(codex_runner.shutil,'which',return_value='/usr/bin/false'):
                with self.assertRaises(ValueError):
                    codex_runner.run({'target':str(root),'goal':'test'}, {'files':[{'path':'a.py','sha256':'wrong'}]}, root/'run', lambda:None, lambda:None, lambda *a:None)

    def test_real_process_adapter_with_explicit_fake_model(self):
        # Protocol fixture only; actual model acceptance is documented separately.
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); fake=root/'fake-codex'
            fake.write_text('''#!/usr/bin/env python3
import sys,json,pathlib
sys.stdin.read()
w=pathlib.Path(sys.argv[sys.argv.index('-C')+1])
(w/'experiments/test.log').write_text('fixture output')
print(json.dumps({'type':'item.completed','item':{'type':'command_execution','command':'fixture','exit_code':0}}),flush=True)
(w/'conclusion.json').write_text(json.dumps({'summary':'fixture','hypotheses':[{'title':'yes','verdict':'supported','explanation':'fixture','artifacts':['experiments/test.log']},{'title':'missing','verdict':'supported','explanation':'fixture','artifacts':['../../outside']}]}))
''');fake.chmod(0o700)
            r={'files':[]}
            with patch.object(codex_runner.shutil,'which',return_value=str(fake)):
                out=codex_runner.run({'target':str(root),'goal':'test'},r,root/'run',lambda:None,lambda:None,lambda *a:None)
            self.assertEqual(out['status'],'completed')
            self.assertEqual(r['hypotheses'][0]['status'],'supported')
            self.assertEqual(r['hypotheses'][1]['status'],'inconclusive')
            self.assertEqual(len(r['agent']['tool_events']),1)
