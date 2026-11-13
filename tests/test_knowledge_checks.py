import unittest
from hybrid_agent import validate_knowledge

class KnowledgeChecksTests(unittest.TestCase):
    def setUp(self):
        self.knowledge=[dict(id='abc',version=2)]
        self.evidence=[dict(id='R1')]
        self.check=dict(id='abc',version=2,status='verified',reason='macOS 目标',attempt='读取 R1 进程身份',conclusion='UID 501',evidence_ids=['R1'],blocker='')
    def validate(self,checks):return validate_knowledge(dict(knowledge_checks=checks),self.knowledge,self.evidence)
    def test_coverage_version_and_evidence(self):
        self.assertEqual(self.validate([self.check]),[self.check])
        for checks in ([],[self.check,self.check],[dict(self.check,version=1)],[dict(self.check,evidence_ids=['fake'])],[dict(self.check,attempt='')],[dict(self.check,blocker='缺少证据')]):
            with self.subTest(checks=checks),self.assertRaises(ValueError):self.validate(checks)
    def test_blocked_and_not_applicable_require_explanation(self):
        self.validate([dict(self.check,status='blocked',evidence_ids=[],blocker='缺少设备，需要采集设备证据')])
        self.validate([dict(self.check,status='not_applicable',reason='限定 iOS，当前为 macOS',evidence_ids=[],attempt='')])
        with self.assertRaises(ValueError):self.validate([dict(self.check,status='blocked')])
