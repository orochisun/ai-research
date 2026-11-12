import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from test_app import app
from demo_workflow import Engine


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data_patch = patch.object(app, 'DATA', Path(self.tmp.name))
        self.data_patch.start()
        app.init_db()
        self.engine = Engine(app.db, app.DB_LOCK)

    def tearDown(self):
        self.data_patch.stop()
        self.tmp.cleanup()

    def create(self):
        return self.engine.create({'target': '/nonexistent/Example.xpc', 'goal': '检查身份绑定'})

    def step(self, rid, count=1):
        for _ in range(count):
            result = self.engine.action(rid, {'action': 'step'})
        return result

    def test_path_is_identifier_and_validated(self):
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('target must not be read')):
            self.assertEqual(self.create()['target'], '/nonexistent/Example.xpc')
        for value in ('', 'relative.xpc', '/tmp/a.txt', 3):
            with self.assertRaises(ValueError): self.engine.create({'target': value})

    def test_existing_binary_uses_input_boundary_fixture(self):
        target = Path(self.tmp.name) / 'FontValidator'
        target.write_bytes(b'not executable')
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('do not read target')):
            r = self.engine.create({'target': str(target)})
            r = self.step(r['id'], 6)
        self.assertEqual(r['scenario'], 'input-boundary')
        self.assertEqual(r['status'], 'waiting_expert')
        self.assertIn('截断输入', r['reviews'][0]['reason'])
        self.assertIn('input=empty', r['artifacts'][-1]['content'])
        self.assertNotIn('caller=administrator', r['artifacts'][-1]['content'])

    def test_review_returns_then_requires_expert(self):
        r = self.create()
        r = self.step(r['id'], 4)
        self.assertEqual(r['reviews'][0]['status'], 'needs_experiment')
        self.assertEqual(r['roles']['experimenter'], 'running')
        r = self.step(r['id'], 2)
        self.assertEqual(r['status'], 'waiting_expert')
        self.assertEqual(r['reviews'][-1]['status'], 'ready_for_expert')
        self.assertEqual(len(r['artifacts']), 3)
        with self.assertRaises(ValueError): self.step(r['id'])
        r = self.engine.action(r['id'], {'action': 'close', 'text': '暂不作安全判断，收束演示'})
        self.assertEqual(r['status'], 'completed')
        self.assertEqual(r['decision'], '暂不作安全判断，收束演示')

    def test_steering_preserves_old_evidence_and_restarts(self):
        r = self.create()
        r = self.step(r['id'], 3)
        old = r['artifacts'][:]
        r = self.engine.action(r['id'], {'action': 'steer', 'text': '改查重启后的授权撤销'})
        self.assertEqual(r['revision'], 2)
        self.assertEqual(r['stage'], 0)
        self.assertEqual(r['history'][0]['stage'], 3)
        self.assertEqual(r['artifacts'], old)
        r = self.step(r['id'], 2)
        self.assertIn('改查重启后的授权撤销', r['plan'][0])
        self.assertEqual(r['artifacts'][-1]['revision'], 2)
        self.assertEqual(r['artifacts'][-1]['focus'], r['focus'])

    def test_note_does_not_replan_and_knowledge_versions(self):
        r = self.create()
        r = self.step(r['id'], 2)
        r = self.engine.action(r['id'], {'action': 'note', 'text': '可能只适用于旧版本'})
        self.assertEqual(r['stage'], 2)
        self.assertEqual(r['revision'], 1)
        k = self.engine.knowledge()[0]
        self.assertEqual(k['original'], '可能只适用于旧版本')
        updated = self.engine.edit_knowledge(k['id'], {'summary': '旧版本经验，适用范围未知', 'scope': 'task', 'status': 'confirmed', 'version': 1})
        self.assertEqual(updated['original'], k['original'])
        self.assertEqual(updated['version'], 2)
        self.assertEqual(updated['history'][0]['summary'], k['original'])
        with self.assertRaises(ValueError):
            self.engine.edit_knowledge(k['id'], {'summary':'stale', 'scope':'task', 'status':'confirmed', 'version':1})

    def test_knowledge_scope_and_confirmation_filter(self):
        r = self.create()
        self.engine.action(r['id'], {'action':'note','text':'专家经验'})
        k = self.engine.knowledge()[0]
        self.assertEqual(self.step(r['id'])['knowledge_refs'], [])
        self.engine.edit_knowledge(k['id'], {'summary':'确认的经验','scope':'task','status':'confirmed','version':1})
        other = self.create()
        self.assertEqual(self.step(other['id'])['knowledge_refs'], [])
        self.engine.action(r['id'], {'action':'steer','text':'继续研究'})
        self.assertEqual(self.step(r['id'])['knowledge_refs'][0]['id'], k['id'])
        self.engine.edit_knowledge(k['id'], {'summary':'确认的经验','scope':'global','status':'confirmed','version':2})
        third = self.create()
        self.assertEqual(self.step(third['id'])['knowledge_refs'][0]['version'], 3)

    def test_pause_persistence_and_tick(self):
        r = self.create()
        self.engine.action(r['id'], {'action':'pause'})
        with patch('demo_workflow.time.time', return_value=10**12): self.engine.tick()
        self.assertEqual(self.engine.get(r['id'])['stage'], 0)
        restored = Engine(app.db, app.DB_LOCK)
        restored.init()
        self.assertEqual(restored.get(r['id'])['status'], 'paused')
        restored.action(r['id'], {'action':'resume'})
        with patch('demo_workflow.time.time', return_value=10**12): restored.tick()
        self.assertEqual(restored.get(r['id'])['stage'], 1)

    def test_invalid_transitions_do_not_archive_knowledge(self):
        r = self.create()
        with self.assertRaises(ValueError): self.engine.action(r['id'], {'action':'close','text':'too early'})
        self.assertEqual(self.engine.knowledge(), [])
        with self.assertRaises(ValueError): self.engine.action(r['id'], {'action':'steer','text':' '})
        self.assertEqual(self.engine.get(r['id'])['revision'], 1)

    def test_http_flow_and_origin(self):
        server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        def post(path, body, origin=None):
            headers = {'Content-Type':'application/json'}
            if origin: headers['Origin'] = origin
            req = urllib.request.Request(base + path, json.dumps(body).encode(), headers)
            with urllib.request.urlopen(req) as response: return json.load(response)
        try:
            r = post('/api/demo/runs', {'target':'/tmp/Demo.xpc'})
            r = post(f"/api/demo/runs/{r['id']}/action", {'action':'steer','text':'代理身份'})
            self.assertEqual(r['revision'], 2)
            with urllib.request.urlopen(base+'/api/demo/knowledge') as response:
                self.assertEqual(json.load(response)[0]['original'], '代理身份')
            with self.assertRaises(urllib.error.HTTPError) as error:
                post('/api/demo/runs', {'target':'/tmp/Demo.xpc'}, 'https://untrusted.example')
            self.assertEqual(error.exception.code, 403)
            error.exception.close()
            for path in ('/', '/legacy', '/demo.js', '/demo.css'):
                with urllib.request.urlopen(base+path) as response: self.assertEqual(response.status, 200)
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__': unittest.main()
