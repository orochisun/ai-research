import copy
import hashlib
import json
from pathlib import Path
import sys
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from test_app import app
from demo_workflow import Engine
import hybrid_agent


def manifest():
    return {'metadata': {'sha256': 'fixture-hash'}, 'evidence': [
        {'id': 'T0', 'title': 'fixture', 'output': 'actual text from tool', 'source': 'tool', 'exit_code': 0}]}


def result():
    return {'summary': 'Explicit unit test fixture', 'plan': ['inspect evidence'],
            'observations': [{'statement': 'a fixture observation', 'evidence_id': 'T0', 'quote': 'actual text'}],
            'inferences': [{'statement': 'fixture inference', 'evidence_ids': ['T0'], 'limitation': 'not verified'}],
            'unknowns': ['runtime'], 'expert_questions': ['next direction?']}


def outcome(role):
    return {'result': result(), 'role': role, 'model': 'gpt-6-luna', 'source': 'model',
            'duration_seconds': 0.1, 'events_path': 'fixture/events.jsonl'}


class HybridTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data_patch = patch.object(app, 'DATA', self.root / 'db')
        self.data_patch.start()
        app.init_db()
        self.engine = Engine(app.db, app.DB_LOCK, lambda: self.root / 'data')
        self.target = self.root / 'binary'
        self.target.write_bytes(struct.pack('<IIIIIIII', 0xFEEDFACF, 0x0100000C, 2, 2, 0, 0, 0, 0) + b'fixture only')

    def tearDown(self):
        self.engine.shutdown()
        self.data_patch.stop()
        self.tmp.cleanup()

    def create(self):
        r = self.engine.create({'target': str(self.target), 'mode': 'hybrid'})
        investigation = {'processes': [], 'launch_definitions': [], 'status': 'incomplete'}
        with patch('hybrid_agent.collect', side_effect=self.collect), patch('runtime_probe.investigate', return_value=investigation), patch('static_analyzer.collect', return_value={'status':'completed','findings':[]}), patch('call_graph.collect', return_value={'status':'collected','findings':[]}), patch('hybrid_agent.run_role') as model:
            self.engine.action(r['id'], {'action': 'step'})
            r = self.wait_job(r['id'])
            self.assertEqual(r['stage'], 1)
            self.assertEqual(r['roles']['investigator'], 'done')
            model.assert_not_called()
        self.engine.action(r['id'], {'action': 'resume'})
        return r

    def collect(self, target, workspace, check, progress):
        check()
        workspace.mkdir(parents=True, exist_ok=True)
        m = manifest()
        m['metadata']['resolved_binary'] = str(self.target)
        (workspace / 'evidence.json').write_text(json.dumps(m))
        return m

    def wait_job(self, rid):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            r = self.engine.get(rid)
            if not r.get('active_job'): return r
            time.sleep(.01)
        self.fail('test worker did not finish')

    def test_x86_rejected_before_model_call(self):
        self.target.write_bytes(struct.pack('<8I', 0xfeedfacf, 0x01000007, 3, 2, 0, 0, 0, 0))
        with patch('hybrid_agent.run_role') as model:
            with self.assertRaisesRegex(ValueError, '拒绝'):
                self.create()
            model.assert_not_called()

    def test_real_roles_and_unresolved_review_cannot_pass(self):
        r = self.create()
        def response(role,*args):
            value=outcome(role)
            value['result']['task_results']=[{'task_index':1,'status':'blocked','conclusion':'unresolved fixture','evidence_ids':['T0'],'attempt':'inspected fixture','blocker':'missing runtime'}]
            return value
        with patch('hybrid_agent.run_role',side_effect=response) as call, patch('verification.collect') as verify:
            for stage in range(2,8):
                self.engine.action(r['id'],{'action':'step'});r=self.wait_job(r['id'])
                self.assertEqual(r['stage'],stage)
            self.assertEqual([c.args[0] for c in call.call_args_list],['planner','analyst','experimenter','reviewer','analyst','reviewer'])
            self.assertEqual(verify.call_count,2)
        self.assertEqual(r['status'],'research_blocked')
        self.assertEqual([x['status'] for x in r['reviews']],['needs_analysis','research_blocked'])
        self.assertNotIn('simulation',{a['source'] for a in r['artifacts']})
        r=self.engine.action(r['id'],{'action':'resume'})
        self.assertEqual(r['stage'],0);self.assertEqual(r['revision'],2)

    def test_scope_limits_do_not_block_completed_plan(self):
        r=self.create()
        with self.engine.lock,self.engine.db() as c:
            r=self.engine._load(c,r['id']);r['stage']=6;r['plan']=['inspect evidence'];self.engine._save(c,r)
        value=outcome('reviewer');value['result']['unknowns']=['Other OS versions were not tested']
        value['result']['task_results']=[{'task_index':1,'status':'observed_runtime','conclusion':'sample complete','evidence_ids':['T0'],'attempt':'actual sample','blocker':''}]
        with patch('hybrid_agent.run_role',return_value=value):
            self.engine.action(r['id'],{'action':'step'});r=self.wait_job(r['id'])
        self.assertEqual(r['status'],'waiting_expert')

    def test_partial_observation_with_blocker_never_passes_review(self):
        r=self.create()
        with self.engine.lock,self.engine.db() as c:
            r=self.engine._load(c,r['id']);r['stage']=6;r['plan']=['inspect evidence'];self.engine._save(c,r)
        value=outcome('reviewer');value['result']['unknowns']=[]
        value['result']['task_results']=[{'task_index':1,'status':'observed_runtime','conclusion':'partial observation','evidence_ids':['T0'],'attempt':'actual sample','blocker':'identity remains unknown'}]
        with patch('hybrid_agent.run_role',return_value=value):
            self.engine.action(r['id'],{'action':'step'});r=self.wait_job(r['id'])
        self.assertEqual(r['status'],'research_blocked')
        self.assertEqual(len(r['reviews'][-1]['gaps']),1)

    def test_steering_during_model_does_not_block_or_publish_stale_result(self):
        started, release = threading.Event(), threading.Event()
        def delayed(role, *args):
            started.set(); release.wait(3)
            return outcome(role)  # intentionally ignores cancellation to test publish guard
        r = self.create()
        with patch('hybrid_agent.collect', side_effect=self.collect), patch('hybrid_agent.run_role', side_effect=delayed):
            self.engine.action(r['id'], {'action': 'step'})
            self.assertTrue(started.wait(2))
            now = time.monotonic()
            changed = self.engine.action(r['id'], {'action': 'steer', 'text': 'new expert direction'})
            self.assertLess(time.monotonic() - now, .5)
            self.assertEqual(changed['revision'], 2)
            release.set()
            for thread in list(self.engine._threads.values()): thread.join(2)
        r = self.engine.get(r['id'])
        self.assertEqual(r['stage'], 0)
        self.assertEqual(r['model_results'], [])
        self.assertEqual(r['focus'], 'new expert direction')
        self.assertEqual(self.engine.knowledge()[0]['source'], 'hybrid')

    def test_pause_cancels_in_flight_model(self):
        started = threading.Event()
        def wait_until_cancelled(role, context, m, workspace, check, progress):
            started.set()
            for _ in range(200): check(); time.sleep(.01)
            raise AssertionError('not cancelled')
        r = self.create()
        self.engine.action(r['id'], {'action': 'pause'})
        with patch('hybrid_agent.collect', side_effect=self.collect), patch('hybrid_agent.run_role', side_effect=wait_until_cancelled):
            self.engine.action(r['id'], {'action': 'resume'})
            self.engine.action(r['id'], {'action': 'step'})
            self.assertTrue(started.wait(2))
            # Pausing also cancels a single-step model job.
            self.engine.action(r['id'], {'action': 'pause'})
            for thread in list(self.engine._threads.values()): thread.join(2)
        self.assertEqual(self.engine.get(r['id'])['status'], 'paused')
        self.assertEqual(self.engine.get(r['id'])['stage'], 1)

    def test_failure_is_visible_without_simulation_fallback(self):
        r = self.create()
        with patch('hybrid_agent.collect', side_effect=self.collect), patch('hybrid_agent.run_role', side_effect=RuntimeError('provider failed')):
            self.engine.action(r['id'], {'action': 'step'})
            r = self.wait_job(r['id'])
        self.assertEqual(r['status'], 'failed')
        self.assertIn('provider failed', r['error'])
        self.assertEqual(r['stage'], 1)
        self.assertTrue(all(a['source'] == 'tool' for a in r['artifacts']))
        r = self.engine.action(r['id'], {'action': 'resume'})
        self.assertEqual(r['status'], 'running')
        self.assertEqual(r['stage'], 1)
        self.assertEqual(r['revision'], 1)
        self.assertIn('manifest_path', r)
        self.assertNotIn('error', r)

    def test_simulation_knowledge_is_excluded_from_real_planner(self):
        demo = self.engine.create({'target': str(self.target)})
        with self.engine.lock, self.engine.db() as c:
            demo['source']='simulation';self.engine._save(c,demo)
        self.engine.action(demo['id'], {'action': 'note', 'text': 'simulated knowledge'})
        k = self.engine.knowledge()[0]
        self.engine.edit_knowledge(k['id'], {'summary': k['summary'], 'status': 'confirmed', 'scope': 'global', 'version': 1})
        r = self.create()
        with patch('hybrid_agent.collect', side_effect=self.collect), patch('hybrid_agent.run_role', side_effect=lambda role,*args: outcome(role)) as call:
            self.engine.action(r['id'], {'action': 'step'})
            r = self.wait_job(r['id'])
        self.assertEqual(r['knowledge_refs'], [])
        self.assertEqual(call.call_args.args[1]['confirmed_knowledge'], [])

    def test_missing_real_target_rejected(self):
        with self.assertRaises((OSError, ValueError)):
            self.engine.create({'target': '/missing/Demo.xpc', 'mode': 'hybrid'})

    def test_collector_snapshots_and_records_missing_tools(self):
        with patch('hybrid_agent.shutil.which', return_value=None):
            m = hybrid_agent.collect(str(self.target), self.root / 'inputs', lambda: None, lambda *args: None)
        self.assertEqual(m['metadata']['sha256'], hashlib.sha256(self.target.read_bytes()).hexdigest())
        self.assertFalse(m['metadata']['target_executed'])
        self.assertEqual(len(m['evidence']), 8)
        self.assertIsNone(m['evidence'][1]['exit_code'])

    def test_observations_require_exact_source_quotes(self):
        hybrid_agent.validate_result(result(), manifest()['evidence'])
        invalid = result(); invalid['observations'][0]['quote'] = 'invented text'
        with self.assertRaises(ValueError): hybrid_agent.validate_result(invalid, manifest()['evidence'])
        invalid = result(); invalid['inferences'][0]['evidence_ids'] = ['T99']
        with self.assertRaises(ValueError): hybrid_agent.validate_result(invalid, manifest()['evidence'])

    def test_invalid_quote_gets_one_real_correction_attempt(self):
        calls = []
        def fake_execute(argv, cwd, stdout, stderr, *args):
            calls.append(cwd)
            answer = result()
            if len(calls) == 1: answer['observations'][0]['quote'] = 'typo'
            (cwd/'result.json').write_text(json.dumps(answer))
            stdout.write_text('')
            stderr.write_text('')
            return 0, 1
        with patch('hybrid_agent.shutil.which', return_value='codex'), patch('hybrid_agent.execute', side_effect=fake_execute):
            output = hybrid_agent.run_role('planner', {}, manifest(), self.root/'role', lambda:None, lambda *a:None)
        self.assertEqual(len(calls), 2)
        self.assertEqual(output['result'], result())
        self.assertFalse(output['attempts'][0]['accepted'])
        self.assertEqual(output['duration_seconds'], 2)
        self.assertIn('typo', (calls[1]/'prompt.txt').read_text())

    def test_full_access_live_output_is_citable_and_persisted(self):
        import re
        m=manifest()
        def fake_execute(argv,cwd,stdout,stderr,*args):
            self.assertEqual(argv[argv.index('-s')+1],'danger-full-access')
            prompt=(cwd/'prompt.txt').read_text()
            self.assertNotIn('不要执行目标或实验',prompt)
            prefix=re.search(r'L[0-9a-f]{8}_',prompt).group()
            answer=result();answer['observations']=[dict(statement='actual live output',evidence_id=prefix+'1',quote='@lines:1-1')]
            (cwd/'result.json').write_text(json.dumps(answer))
            stdout.write_text(json.dumps(dict(type='item.completed',item=dict(type='command_execution',command='cat profile',exit_code=0,aggregated_output='actual profile rule'))))
            stderr.write_text('');return 0,1
        with patch('hybrid_agent.shutil.which',return_value='codex'),patch('hybrid_agent.execute',side_effect=fake_execute):
            answer=hybrid_agent.run_role('planner',{},m,self.root/'live',lambda:None,lambda *a:None)
        self.assertEqual(answer['result']['observations'][0]['quote'],'actual profile rule')
        self.assertEqual(m['evidence'][-1]['output'],'actual profile rule')

    def test_correction_is_bounded_and_never_accepts_invalid_quote(self):
        def fake_execute(argv, cwd, stdout, stderr, *args):
            answer = result(); answer['observations'][0]['quote'] = 'invented'
            (cwd/'result.json').write_text(json.dumps(answer))
            stdout.write_text(''); stderr.write_text('')
            return 0, 1
        with patch('hybrid_agent.shutil.which', return_value='codex'), patch('hybrid_agent.execute', side_effect=fake_execute) as execute:
            with self.assertRaisesRegex(ValueError, '自动纠错后仍未通过'):
                hybrid_agent.run_role('planner', {}, manifest(), self.root/'role', lambda:None, lambda *a:None)
        self.assertEqual(execute.call_count, 2)
        repair=(self.root/'role/retry-2/prompt.txt').read_text()
        self.assertIn('不是重新开展研究',repair)
        self.assertIn('rejected_result',repair)

    def test_citation_line_locator_materializes_exact_original(self):
        answer=result();answer['observations'][0]['quote']='@lines:2-3'
        evidence=[{'id':'T0','output':'header\n\tquoted "symbol"\nnext line\nfooter'}]
        hybrid_agent.validate_result(answer,evidence)
        self.assertEqual(answer['observations'][0]['quote'],'\tquoted "symbol"\nnext line')
        for locator in ('@lines:0-1','@lines:3-2','@lines:1-99'):
            answer=result();answer['observations'][0]['quote']=locator
            with self.assertRaises(ValueError):hybrid_agent.validate_result(answer,evidence)

    def test_legacy_truncated_evidence_keeps_old_numbers_and_adds_full_file(self):
        raw=self.root/'legacy.stdout.txt';raw.write_text('first\nsecond\ntail\n')
        m={'evidence':[dict(id='T7',title='disassembly',output='old header\nfirst',truncated=True,exit_code=0,stdout_path=str(raw))]}
        hybrid_agent.index_legacy_files(m);hybrid_agent.index_legacy_files(m)
        self.assertEqual(len(m['evidence']),2)
        self.assertEqual(m['evidence'][0]['output'],'old header\nfirst')
        answer=result();answer['inferences']=[];answer['observations']=[dict(statement='tail',evidence_id='T7F',quote='@lines:3-3')]
        hybrid_agent.validate_result(answer,m['evidence'])
        self.assertEqual(answer['observations'][0]['quote'],'tail')

    def test_disjoint_citations_keep_explicit_boundaries(self):
        evidence=[{'id':'T0','output':'first\nnot cited\nthird\n'}]
        answer=result();answer['observations'][0]['quote']='@lines:1-1\n@lines:3-3'
        hybrid_agent.validate_result(answer,evidence)
        self.assertEqual(answer['observations'][0]['quote'],'[@lines:1-1]\nfirst\n\n[@lines:3-3]\nthird')
        answer=result();answer['observations'][0]['quote']='@lines:1-1,3-3'
        hybrid_agent.validate_result(answer,evidence)
        self.assertIn('[@lines:3-3]\nthird',answer['observations'][0]['quote'])
        answer=result();answer['observations'][0]['quote']='@lines:1-1\n@lines:4-4'
        with self.assertRaises(ValueError):hybrid_agent.validate_result(answer,evidence)

    def test_static_output_limit_retains_partial_evidence_and_continues(self):
        def execute(argv,cwd,stdout,stderr,*args,**kwargs):
            stdout.write_text('captured ARM disassembly');stderr.write_text('')
            if '-tvV' in argv:raise hybrid_agent.OutputLimitExceeded('bounded output')
            return 0,.1
        with patch('hybrid_agent.shutil.which',side_effect=lambda x:x),patch('hybrid_agent.execute',side_effect=execute):
            m=hybrid_agent.collect(str(self.target),self.root/'partial',lambda:None,lambda *a:None)
        t7=next(e for e in m['evidence'] if e['id']=='T7')
        self.assertEqual(t7['capture_status'],'partial');self.assertEqual(t7['stop_reason'],'output_limit')
        self.assertTrue(t7['truncated']);self.assertIsNone(t7['exit_code'])
        self.assertIn('partial',t7['output']);self.assertIn('captured ARM disassembly',t7['output'])
        self.assertTrue((self.root/'partial/evidence.json').exists())

    def test_large_static_output_is_complete_file_and_tail_is_citable(self):
        text='head\n'+'instruction\n'*100+'tail sentinel\n'
        def execute(argv,cwd,stdout,stderr,*args,**kwargs):
            self.assertIsNone(kwargs['output_limit'])
            stdout.write_text(text);stderr.write_text('');return 0,.1
        with patch('hybrid_agent.MAX_OUTPUT',50),patch('hybrid_agent.shutil.which',side_effect=lambda x:x),patch('hybrid_agent.execute',side_effect=execute):
            m=hybrid_agent.collect(str(self.target),self.root/'full',lambda:None,lambda *a:None)
        t7=next(e for e in m['evidence'] if e['id']=='T7')
        self.assertFalse(t7['truncated']);self.assertEqual(t7['capture_status'],'complete')
        self.assertEqual(t7['content_storage'],'file');self.assertEqual(Path(t7['line_source_path']).read_text(),text)
        answer=result();answer['observations']=[dict(statement='tail exists',evidence_id='T7',quote='@lines:102-102')]
        hybrid_agent.validate_result(answer,m['evidence'])
        self.assertEqual(answer['observations'][0]['quote'],'tail sentinel')
        answer=result();answer['observations']=[dict(statement='head and tail',evidence_id='T7',quote='@lines:1-1\n@lines:102-102')]
        hybrid_agent.validate_result(answer,m['evidence'])
        self.assertIn('[@lines:102-102]\ntail sentinel',answer['observations'][0]['quote'])
        answer=result();answer['observations']=[dict(statement='too much',evidence_id='T7',quote='@lines:1-41\n@lines:42-82')]
        with self.assertRaises(ValueError):hybrid_agent.validate_result(answer,m['evidence'])

    def test_file_capture_can_exceed_default_limit_without_losing_bytes(self):
        with patch('hybrid_agent.MAX_EXEC_OUTPUT',1024):
            code,_=hybrid_agent.execute([sys.executable,'-c','import os,time; os.write(1,b"x"*2048); time.sleep(.3)'],
                self.root,self.root/'full.stdout',self.root/'full.stderr',lambda:None,5,output_limit=None)
        self.assertEqual(code,0);self.assertEqual((self.root/'full.stdout').stat().st_size,2048)

    def test_real_output_limit_stops_child_and_keeps_logs(self):
        with patch('hybrid_agent.MAX_EXEC_OUTPUT',1024),self.assertRaises(hybrid_agent.OutputLimitExceeded):
            hybrid_agent.execute([sys.executable,'-c','import os,time; os.write(1,b"x"*2048); time.sleep(30)'],
                self.root,self.root/'large.stdout',self.root/'large.stderr',lambda:None,5)
        self.assertEqual((self.root/'large.stdout').stat().st_size,2048)

    def test_cancelled_subprocess_is_reaped(self):
        calls = []
        def check():
            calls.append(1)
            if len(calls) >= 3: raise hybrid_agent.Superseded()
        with self.assertRaises(hybrid_agent.Superseded):
            hybrid_agent.execute([sys.executable, '-c', 'import time; time.sleep(30)'], self.root,
                                 self.root/'stdout', self.root/'stderr', check, 3)
        self.assertGreaterEqual(len(calls), 3)


if __name__ == '__main__': unittest.main()
