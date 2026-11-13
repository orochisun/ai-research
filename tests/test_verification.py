import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
import hybrid_agent
import verification

class VerificationTests(unittest.TestCase):
    def test_unsupported_target_has_evidence_blocker_and_no_fabricated_result(self):
        with tempfile.TemporaryDirectory() as d:
            m={'metadata':{'resolved_binary':'/unknown/target'},'evidence':[]};execute=Mock()
            r=verification.collect(m,Path(d),lambda:None,lambda *a:None,execute)
            self.assertEqual(r['status'],'blocked');self.assertTrue(r['blockers']);self.assertEqual(r['attempts'],[])
            execute.assert_not_called();self.assertEqual(m['evidence'][-1]['id'],'V1')
    def test_plan_receipts_reject_missing_and_unknown_evidence(self):
        evidence=[{'id':'C2'}];plan=['trace field','measure reply']
        task={'task_index':1,'status':'blocked','conclusion':'missing','attempt':'read function','blocker':'no runtime','evidence_ids':['C2']}
        with self.assertRaises(ValueError):hybrid_agent.validate_tasks({'task_results':[task]},plan,evidence)
        second={**task,'task_index':2}
        self.assertEqual(len(hybrid_agent.validate_tasks({'task_results':[task,second]},plan,evidence)),2)
        with self.assertRaises(ValueError):hybrid_agent.validate_tasks({'task_results':[task,{**second,'evidence_ids':['missing']}]},plan,evidence)
        with self.assertRaises(ValueError):hybrid_agent.validate_tasks({'task_results':[task,{**second,'blocker':''}]},plan,evidence)
