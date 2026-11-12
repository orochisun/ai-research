import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch
import static_analyzer as sa
import hybrid_agent
from test_app import app
from demo_workflow import Engine

class StaticAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.target=self.root/'input with spaces.arm'
        self.target.write_bytes(struct.pack('<8I',0xfeedfacf,0x0100000c,2,2,0,0,0,0))
        self.script=self.root/'fixture.py'
        self.script.write_text('import json,sys\nfrom pathlib import Path\np=Path(sys.argv[1]); assert p.read_bytes()[4:8]==bytes.fromhex("0c000001")\nr=json.dumps({"fixture":True,"path":str(p),"coverage":"partial","findings":[]})\nif len(sys.argv)>2: Path(sys.argv[2]).write_text(r)\nelse: print(r)\n')
    def tearDown(self):self.tmp.cleanup()
    def config(self,**kw):return {**sa.DEFAULT,'enabled':True,'executable':sys.executable,'args':[str(self.script),'{arm_binary}'],**kw}
    def run_tool(self,c,execute=hybrid_agent.execute):
        m={'metadata':{'sha256':hashlib.sha256(self.target.read_bytes()).hexdigest()},'evidence':[{'id':'T1','argv':['file',str(self.target)]}]}
        r=sa.collect(m,self.root/uuid.uuid4().hex,lambda:None,lambda *a:None,execute,c)
        return r,m
    def test_actual_process_stdout_and_file(self):
        r,m=self.run_tool(self.config())
        self.assertEqual(r['status'],'executed');self.assertTrue(r['report']['fixture']);self.assertEqual(r['coverage'],'unknown')
        self.assertEqual(m['evidence'][-1]['id'],'S1')
        r,m=self.run_tool(self.config(args=[str(self.script),'{arm_binary}','{output_file}'],output='reports/result.json'))
        self.assertEqual(r['report']['coverage'],'partial');self.assertTrue(Path(r['report_path']).exists())
    def test_text_and_ndjson(self):
        for fmt in ('text','ndjson'):
            r,_=self.run_tool(self.config(format=fmt));self.assertEqual(r['status'],'executed')
            self.assertIsInstance(r['report'],str if fmt=='text' else list)
    def test_disabled_and_x86_never_execute(self):
        with patch('hybrid_agent.execute') as execute:
            r,_=self.run_tool(sa.DEFAULT,execute);self.assertEqual(r['status'],'disabled');execute.assert_not_called()
            self.target.write_bytes(struct.pack('<8I',0xfeedfacf,0x01000007,3,2,0,0,0,0))
            r,_=self.run_tool(self.config(),execute);self.assertEqual(r['status'],'invalid_output');execute.assert_not_called()
    def test_timeout_and_cancellation(self):
        self.script.write_text('import time\ntime.sleep(30)\n')
        r,_=self.run_tool(self.config(timeout_seconds=1));self.assertEqual(r['status'],'timeout')
        def cancelled(*a):raise hybrid_agent.Superseded()
        with self.assertRaises(hybrid_agent.Superseded):self.run_tool(self.config(),cancelled)
    def test_bad_output_and_nonzero_exit(self):
        self.script.write_text('print("not JSON")\n')
        r,_=self.run_tool(self.config());self.assertEqual(r['status'],'invalid_output')
        self.script.write_text('import sys\nprint("{}")\nsys.exit(3)\n')
        r,_=self.run_tool(self.config());self.assertEqual(r['status'],'failed');self.assertEqual(r['exit_code'],3)
    def test_validation(self):
        for changes in ({'args':'shell command'},{'args':['{unknown}']},{'output':'../outside.json'},{'timeout_seconds':0},{'executable':'relative'},{'format':'xml'}):
            with self.assertRaises(ValueError):sa.validate(self.config(**changes))
    def test_saved_config_snapshot_and_new_revision(self):
        with patch.object(app,'DATA',self.root/'db'):
            app.init_db();engine=Engine(app.db,app.DB_LOCK)
            first=self.config(name='first');engine.tool_config(first)
            run=engine.create({'target':str(self.target),'mode':'hybrid'})
            engine.tool_config(self.config(name='second'))
            self.assertEqual(engine.get(run['id'])['static_tool_config']['name'],'first')
            engine2=Engine(app.db,app.DB_LOCK)
            self.assertEqual(engine2.tool_config()['name'],'second')
            run=engine.action(run['id'],{'action':'steer','text':'fixture direction'})
            self.assertEqual(run['static_tool_config']['name'],'second')
