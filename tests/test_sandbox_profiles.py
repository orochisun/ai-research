import json
import tempfile
import unittest
from pathlib import Path
import sandbox_profiles
import hybrid_agent

class EvidenceTests(unittest.TestCase):
    def test_profiles_include_imports_and_explicit_missing_error(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'application.sb').write_text('(import "common.sb")\n; (import "ignored.sb")\n(import "missing.sb")')
            (root/'common.sb').write_text('(import "application.sb")\n(allow file-read*)')
            m={'evidence':[]};sandbox_profiles.collect(m,root/'out',lambda:None,root)
            self.assertEqual(len(m['evidence']),3)
            self.assertIn('(allow file-read*)',m['evidence'][1]['output'])
            self.assertEqual(m['evidence'][2]['exit_code'],1)
            sandbox_profiles.collect(m,root/'out',lambda:None,root)
            self.assertEqual(len(m['evidence']),3)
    def test_live_evidence_is_command_output_not_model_summary(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);events=root/'events.jsonl'
            events.write_text('\n'.join(json.dumps(e) for e in [
                {'type':'item.completed','item':{'type':'agent_message','text':'not evidence'}},
                {'type':'item.completed','item':{'type':'command_execution','command':'cat profile','exit_code':0,'aggregated_output':'actual rule\n'}},
                {'type':'item.completed','item':{'type':'command_execution','command':'false','exit_code':1,'aggregated_output':'failure'}}]))
            evidence=hybrid_agent.capture_live_evidence(events,'Ltest_',root)
            self.assertEqual([e['id'] for e in evidence],['Ltest_1','Ltest_2'])
            self.assertEqual(evidence[0]['output'],'actual rule\n');self.assertEqual(evidence[1]['exit_code'],1)
            self.assertEqual(Path(evidence[0]['record_path']).read_text(),'actual rule\n')
