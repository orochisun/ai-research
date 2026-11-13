import json
from pathlib import Path
import tempfile
import unittest
from evidence_capture import LiveEvidenceRecorder
from hybrid_agent import validate_tasks


class EvidenceCaptureTests(unittest.TestCase):
    def test_partial_events_failed_commands_and_repeated_poll_keep_stable_receipts(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);events=root/'events.jsonl'
            recorder=LiveEvidenceRecorder(events,'Ltest_',root)
            event=json.dumps({'type':'item.completed','item':{'id':'item_7','type':'command_execution','command':'failed probe','exit_code':1,'aggregated_output':'actual error\n'}})
            events.write_text(event[:30]);recorder.poll()
            self.assertEqual(recorder.records,[])
            with events.open('a') as stream:stream.write(event[30:]+'\n'+event+'\n')
            recorder.poll();recorder.poll()
            index=json.loads((root/'live-evidence-index.json').read_text())
            self.assertEqual(len(index),1)
            self.assertEqual(index[0]['id'],'Ltest_1')
            self.assertEqual(index[0]['exit_code'],1)
            self.assertEqual(Path(index[0]['line_source_path']).read_text(),'actual error\n')

    def test_large_live_output_has_complete_citable_file(self):
        from hybrid_agent import validate_result
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);events=root/'events.jsonl';output='a'*9000+'\ntail\n'
            events.write_text(json.dumps({'type':'item.completed','item':{'id':'x','type':'command_execution','command':'large output','exit_code':0,'aggregated_output':output}}))
            recorder=LiveEvidenceRecorder(events,'Ltest_',root);recorder.poll()
            evidence=recorder.records[0]
            self.assertEqual(evidence['content_storage'],'file')
            self.assertEqual(Path(evidence['line_source_path']).read_text(),output)
            result=dict(summary='tail',plan=['read'],observations=[dict(statement='tail',evidence_id='Ltest_1',quote='@lines:2-2')],inferences=[],unknowns=[],expert_questions=[])
            validate_result(result,recorder.records)
            self.assertEqual(result['observations'][0]['quote'],'tail')

    def test_receipt_is_published_before_child_exits(self):
        import sys
        from hybrid_agent import execute
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);events=root/'events.jsonl'
            recorder=LiveEvidenceRecorder(events,'Ltest_',root)
            script="""import json,time,pathlib
print(json.dumps({'type':'item.completed','item':{'id':'x','type':'command_execution','command':'probe','exit_code':0,'aggregated_output':'probe done'}}),flush=True)
for _ in range(30):
 if json.loads(pathlib.Path('live-evidence-index.json').read_text()):break
 time.sleep(.1)
else:raise RuntimeError('receipt was not published while executing')
"""
            code,_=execute([sys.executable,'-c',script],root,events,root/'stderr',lambda:None,5,on_output=recorder.poll)
            self.assertEqual(code,0)
            self.assertEqual(recorder.records[0]['id'],'Ltest_1')

    def test_non_applicable_needs_evidence_and_cannot_hide_blocker(self):
        task=dict(task_index=1,status='not_applicable',conclusion='工具未启用，不依赖报告',attempt='读取配置',evidence_ids=['S1'],blocker='')
        validate_tasks({'task_results':[task]},['若启用工具则检查报告'],[{'id':'S1'}])
        for bad in [dict(task,blocker='缺少适用证据'),dict(task,evidence_ids=[]),dict(task,task_index=True)]:
            with self.assertRaises(ValueError):validate_tasks({'task_results':[bad]},['检查'],[{'id':'S1'}])
