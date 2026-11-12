import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('nexus', Path(__file__).resolve().parents[1] / 'app.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        app.DATA = self.root / 'db'
        self.env = patch.dict(os.environ, {'NEXUS_ALLOWED_ROOTS': str(self.root), 'NEXUS_MODEL_BASE_URL': '', 'NEXUS_MODEL': ''})
        self.env.start()
        app.init_db()
        self.target = self.root / 'sample.py'
        self.target.write_text('import subprocess\nsubprocess.run(["git", "--version"])\n', encoding='utf-8')

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def task(self, mode='local'):
        return app.create_task({'target': str(self.target), 'mode': mode})

    def test_end_to_end_evidence_report_persistence(self):
        t = self.task()
        app.run_task(t['id'])
        t = app.get_task(t['id'])
        self.assertEqual(t['status'], 'completed')
        self.assertEqual(t['result']['evidence'][0]['line'], 2)
        self.assertEqual(t['result']['hypotheses'][0]['status'], 'unverified')
        self.assertIn('sample.py:2', app.report(t))
        app.init_db()
        self.assertEqual(app.get_task(t['id'])['result'], t['result'])

    def test_model_missing_preserves_results(self):
        t = self.task('ai')
        app.run_task(t['id'])
        t = app.get_task(t['id'])
        self.assertEqual(t['status'], 'completed_with_warnings')
        self.assertTrue(t['result']['evidence'])

    def test_scope_and_symlink(self):
        with self.assertRaises(ValueError): app.validate_target('/etc/passwd')
        link = self.root / 'escape.py'
        link.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError): app.validate_target(str(link))

    def test_cancelled_task_never_runs(self):
        t = self.task()
        app.update(t['id'], status='cancelled', cancel=1)
        app.run_task(t['id'])
        self.assertEqual(app.get_task(t['id'])['status'], 'cancelled')
        self.assertFalse(app.get_task(t['id'])['result'])

    def test_recovery(self):
        t = self.task()
        app.update(t['id'], status='running')
        app.init_db()
        self.assertEqual(app.get_task(t['id'])['status'], 'interrupted')

    def test_binary_and_budget(self):
        self.target.write_bytes(b'\x7fELF' + b'hello world')
        self.target = self.target.rename(self.root / 'sample.bin')
        t = self.task()
        r = app.analyze(self.target, t['id'])
        self.assertEqual(r['files'][0]['kind'], 'ELF')
        self.target.write_bytes(b'x' * (1024 * 1024 + 1))
        r = app.analyze(self.target, t['id'])
        self.assertEqual(len(r['skipped']), 1)

    def test_model_response_and_unknown_reference(self):
        t = self.task()
        r = app.analyze(self.target, t['id'])
        answer = {'summary': 'Test', 'hypotheses': [{'title':'Check inputs','evidence_ids':['E1'],'validation':'Trace arguments'}, {'title':'Bad','evidence_ids':['E999'],'validation':'Unknown'}]}
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, _): return json.dumps({'choices':[{'message':{'content':json.dumps(answer)}}]}).encode()
        with patch.dict(os.environ, {'NEXUS_MODEL_BASE_URL':'http://localhost:9999/v1','NEXUS_MODEL':'test'}), patch.object(urllib.request, 'urlopen', return_value=Response()) as call:
            result = app.ai_review(t['request'], r)
            self.assertEqual(result['accepted'], 1)
            self.assertEqual(result['rejected'], 1)
            self.assertEqual(call.call_args.args[0].full_url, 'http://localhost:9999/v1/chat/completions')

    def test_http_creation_exports_and_origin(self):
        server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            payload = json.dumps({'target': str(self.target)}).encode()
            req = urllib.request.Request(base + '/api/tasks', payload, {'Content-Type':'application/json'})
            with urllib.request.urlopen(req) as response: t = json.load(response)
            app.run_task(t['id'])
            with urllib.request.urlopen(base + '/api/tasks/' + t['id'] + '/export') as response:
                self.assertEqual(json.load(response)['status'], 'completed')
            bad = urllib.request.Request(base + '/api/tasks', payload, {'Origin':'https://untrusted.example'})
            with self.assertRaises(urllib.error.HTTPError) as error: urllib.request.urlopen(bad)
            self.assertEqual(error.exception.code, 403)
            with urllib.request.urlopen(base + '/') as response: self.assertIn('星枢', response.read().decode())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

if __name__ == '__main__': unittest.main()
