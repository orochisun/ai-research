"""Real-only workflow API, knowledge persistence and transitions."""
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_app import app
from demo_workflow import Engine

class DemoTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.data_patch=patch.object(app,'DATA',self.root);self.data_patch.start();app.init_db()
        self.engine=Engine(app.db,app.DB_LOCK)
        self.target=self.root/'target';self.target.write_bytes(struct.pack('<8I',0xfeedfacf,0x0100000c,2,2,0,0,0,0))
    def tearDown(self):self.engine.shutdown();self.data_patch.stop();self.tmp.cleanup()
    def create(self):return self.engine.create({'target':str(self.target)})
    def test_real_default_and_simulation_rejected(self):
        r=self.create();self.assertEqual(r['mode'],'hybrid');self.assertEqual(r['model'],'gpt-6-luna')
        with self.assertRaises(ValueError):self.engine.create({'target':str(self.target),'mode':'simulation'})
    def test_invalid_close_does_not_archive_knowledge(self):
        r=self.create()
        with self.assertRaises(ValueError):self.engine.action(r['id'],{'action':'close','text':'early'})
        self.assertEqual(self.engine.knowledge(),[])
    def test_steer_keeps_history_and_expert_original(self):
        r=self.create();r=self.engine.action(r['id'],{'action':'steer','text':'追踪返回路径'})
        self.assertEqual(r['revision'],2);self.assertEqual(len(r['history']),1)
        self.assertEqual(self.engine.knowledge()[0]['original'],'追踪返回路径')
    def test_note_and_version_conflict(self):
        r=self.create();self.engine.action(r['id'],{'action':'note','text':'版本范围未知'})
        k=self.engine.knowledge()[0]
        updated=self.engine.edit_knowledge(k['id'],{'summary':'核对版本','scope':'task','status':'confirmed','version':1})
        self.assertEqual(updated['original'],'版本范围未知');self.assertEqual(updated['version'],2)
        with self.assertRaises(ValueError):self.engine.edit_knowledge(k['id'],{'summary':'stale','scope':'task','status':'confirmed','version':1})
    def test_pause_survives_restart(self):
        r=self.create();self.engine.action(r['id'],{'action':'pause'})
        restored=Engine(app.db,app.DB_LOCK);restored.init()
        self.assertEqual(restored.get(r['id'])['status'],'paused')
    def test_global_knowledge_create_edit_and_retire(self):
        k=self.engine.create_knowledge({'original':'macOS：先按运行时证据验证 UID，再调查 IPC。'})
        self.assertEqual(k['scope'],'global');self.assertEqual(k['status'],'confirmed')
        self.assertIsNone(k['run_id'])
        with app.db() as c:self.assertEqual(self.engine._confirmed_knowledge(c,'another')[0]['original'],k['original'])
        with self.assertRaises(ValueError):self.engine.create_knowledge({'original':' '})
        with self.assertRaises(ValueError):self.engine.edit_knowledge(k['id'],dict(summary='x',scope='task',status='confirmed',version=1))
        self.engine.edit_knowledge(k['id'],dict(summary='更新方法',scope='global',status='confirmed',version=1))
        with app.db() as c:
            latest=self.engine._confirmed_knowledge(c,'another')[0]
            self.assertEqual(latest['version'],2);self.assertEqual(latest['summary'],'更新方法')
        self.engine.edit_knowledge(k['id'],dict(summary='更新方法',scope='global',status='retired',version=2))
        with app.db() as c:self.assertEqual(self.engine._confirmed_knowledge(c,'another'),[])

    def test_every_stage_refreshes_global_knowledge(self):
        r=self.create();k=self.engine.create_knowledge({'original':'根据实际进程验证 UID'})
        for stage in range(len(r['stages'])):
            r['stage']=stage;r['active_job']=None;self.engine._threads.clear()
            with patch('demo_workflow.threading.Thread') as thread, app.db() as c:
                self.engine._start_model(c,r)
                snapshot=thread.call_args.kwargs['args'][0]
                self.assertEqual(snapshot['knowledge_refs'][0]['id'],k['id'])
                self.assertEqual(snapshot['knowledge_refs'][0]['original'],k['original'])
        self.engine._threads.clear()
