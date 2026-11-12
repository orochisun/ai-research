import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import dagger_adapter as d

class DaggerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.target=self.root/'target.arm';self.target.write_bytes(struct.pack('<8I',0xfeedfacf,0x0100000c,2,2,0,0,0,0))
    def tearDown(self):self.tmp.cleanup()
    def manifest(self):return {'metadata':{'sha256':hashlib.sha256(self.target.read_bytes()).hexdigest()},'evidence':[{'id':'T1','argv':['file',str(self.target)]}]}
    def event(self,kind,**kw):return json.dumps(dict(schema='dagger.audit.stream',schema_version=1,type=kind,**kw))+'\n'
    def test_complete_report_and_real_failure_are_distinct(self):
        def execute(argv,cwd,out,err,*args):
            out.write_text(self.event('audit_done',total=0)+self.event('audit_summary',report={'findings':[],'summary':{'total':0},'coverage':{'scope':'fixture'}}));err.write_text('');return 0,.1
        with patch('dagger_adapter.executable',return_value=self.target):
            r=d.collect(self.manifest(),self.root/'ok',lambda:None,lambda *a:None,execute)
            self.assertEqual(r['status'],'completed')
            def crash(argv,cwd,out,err,*args):
                if '--help' in argv:out.write_text('--detail');return 0,.1
                out.write_text(self.event('audit_started'));err.write_text('panic fixture');return 134,.1
            r=d.collect(self.manifest(),self.root/'fail',lambda:None,lambda *a:None,crash)
            self.assertEqual(r['status'],'failed');self.assertIn('panic',r['diagnostic'])
    def test_deadline_not_clean_completion(self):
        p=self.root/'stream';p.write_text(self.event('scanning',deadline_reached=True)+self.event('audit_done'))
        self.assertTrue(d.parse_stream(p)['limited'])
    def test_v4_partial_zero_findings_is_incomplete(self):
        p=self.root/'stream'
        events=[('run.open',{'schema_version':2}),('run.close',{'outcome':'complete','findings':0,'coverage':{'status':'partial','limitations':['unresolved operations']}})]
        p.write_text(''.join(json.dumps({'protocolVersion':4,'runId':'test','sequence':i,'event':{'kind':k,'payload':v}})+'\n' for i,(k,v) in enumerate(events)))
        parsed=d.parse_stream(p)
        self.assertTrue(parsed['done']);self.assertTrue(parsed['limited'])
        self.assertEqual(parsed['report']['findings'],[])
        frames=p.read_text().replace('"sequence": 1','"sequence": 3')
        p.write_text(frames)
        with self.assertRaises(ValueError):d.parse_stream(p)

    def test_unrelated_cli_output_rejected(self):
        p=self.root/'stream';p.write_text('{"type":"done"}\n')
        with self.assertRaises(ValueError):d.parse_stream(p)
    def test_x86_is_rejected_before_engine_execution(self):
        self.target.write_bytes(struct.pack('<8I',0xfeedfacf,0x01000007,3,2,0,0,0,0))
        with patch('dagger_adapter.executable',return_value=self.target),patch('hybrid_agent.execute') as call:
            with self.assertRaises(ValueError):d.collect(self.manifest(),self.root/'x86',lambda:None,lambda *a:None,call)
            call.assert_not_called()
    def test_missing_engine_is_explicit(self):
        with patch('dagger_adapter.executable',return_value=None):
            m=self.manifest();r=d.collect(m,self.root/'none',lambda:None,lambda *a:None,None)
        self.assertEqual(r['status'],'unavailable');self.assertEqual(m['evidence'][-1]['id'],'D1')
