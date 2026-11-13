"""Persistent simulated or hybrid multi-agent research workflows."""
import copy
import json
import threading
import hybrid_agent
import runtime_probe
import call_graph
import static_analyzer
import verification
import sandbox_profiles
from pathlib import Path
import time
import uuid

ROLES = ['planner', 'analyst', 'experimenter', 'reviewer', 'knowledge']
STAGES = ['plan', 'analyze', 'experiment', 'review', 'supplement', 'recheck']


def text_field(body, name, limit=2000, required=True):
    value = body.get(name, '')
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise ValueError(f'{name} 必须是非空文本，且不超过 {limit} 字符')
    return value.strip()


class Engine:
    def __init__(self, db, lock, data_root=None):
        self.db, self.lock = db, lock
        self.data_root = data_root or (lambda: Path(__file__).parent / "data")
        self._threads = {}
        self._closing = threading.Event()

    def init(self):
        with self.db() as c:
            c.execute('CREATE TABLE IF NOT EXISTS tool_settings (name TEXT PRIMARY KEY, body TEXT NOT NULL)')
            c.execute('CREATE TABLE IF NOT EXISTS demo_runs (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
            c.execute('CREATE TABLE IF NOT EXISTS expert_knowledge (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
            for row in c.execute('SELECT body FROM demo_runs').fetchall():
                run = json.loads(row[0])
                if run.get('mode')!='hybrid' and run['status']=='running':
                    run['status']='paused';self._save(c,run)
                if run.get('active_job'):
                    run['active_job'] = None
                    run['status'] = 'paused'
                    self._event(run, 'planner', '模型调用被重启中断', '请恢复执行以重新调用；不会使用未完成结果。', source='system')
                    self._save(c, run)

    def _load(self, c, rid):
        row = c.execute('SELECT body FROM demo_runs WHERE id=?', (rid,)).fetchone()
        if not row:
            raise ValueError('研究不存在')
        return json.loads(row[0])

    def _save(self, c, run):
        run['updated'] = time.time()
        c.execute('INSERT OR REPLACE INTO demo_runs VALUES (?,?)', (run['id'], json.dumps(run, ensure_ascii=False)))

    def _event(self, run, role, title, detail, refs=None, source=None):
        run['events'].append({'id': 'EV' + str(len(run['events']) + 1), 'time': time.time(),
                              'revision': run['revision'], 'role': role, 'title': title,
                              'detail': detail, 'refs': refs or [], 'source': source or ('expert' if role == 'expert' else 'system')})

    def _artifact(self, run, kind, title, content, source="tool"):
        artifact = {'id': 'E' + str(len(run['artifacts']) + 1), 'revision': run['revision'],
                    'kind': kind, 'title': title, 'content': content, 'source': source,
                    'focus': run['focus'], 'target': run['target']}
        run['artifacts'].append(artifact)
        return artifact['id']

    def create(self, body):
        target = text_field(body, 'target', 4096).rstrip('/')
        mode = body.get('mode', 'hybrid')
        if mode != 'hybrid': raise ValueError('仅支持真实 Luna 研究，模拟模式已移除')
        if mode == 'hybrid':
            binary = hybrid_agent.binary_path(target)
            with binary.open('rb') as stream:
                hybrid_agent.select_arm(stream.read(hybrid_agent.MAX_BINARY + 1))
        is_xpc = Path(target).suffix.lower() == '.xpc'
        if not Path(target).is_absolute() or (not is_xpc and not Path(target).is_file()):
            raise ValueError('请输入 .xpc 绝对路径或已存在的文件绝对路径')
        focus = text_field(body, 'goal', required=False) or ('检查 XPC 服务的调用者身份、代理转发和权限边界' if is_xpc else '梳理输入处理与边界验证条件')
        now = time.time()
        run = {'id': uuid.uuid4().hex[:12], 'target': target, 'focus': focus, 'created': now,
               'scenario': 'xpc' if is_xpc else 'input-boundary', 'revision': 1, 'stage': 0, 'status': 'running', 'next_at': now + 2,
               'roles': {r: 'pending' for r in ROLES}, 'events': [], 'artifacts': [],
               'reviews': [], 'messages': [], 'history': [], 'plan': [], 'knowledge_refs': [],
               'source': 'hybrid', 'mode': mode,
               'model': hybrid_agent.MODEL if mode == 'hybrid' else None, 'active_job': None, 'model_results': [], 'decision': None}
        if mode == 'hybrid':
            run['stages'] = ['investigate', *STAGES]
            run['roles'] = {'investigator': 'pending', **run['roles']}
        self._event(run, 'planner', '研究已创建', '默认先自动调查运行身份、权限、sandbox 与 IPC，再由 gpt-6-luna 规划分析；所有环节使用真实证据；不支持的实验明确记录阻塞。' if mode == 'hybrid' else '输入仅作为目标标识；不会读取内容、运行或分析该目标。', source='system')
        run['static_tool_config'] = self.tool_config()
        with self.lock, self.db() as c:
            self._save(c, run)
        return run

    def tool_config(self, value=None):
        with self.lock, self.db() as c:
            if value is not None:
                config = static_analyzer.validate(value)
                c.execute('INSERT OR REPLACE INTO tool_settings VALUES (?,?)', ('static', json.dumps(config)))
                return config
            row = c.execute('SELECT body FROM tool_settings WHERE name=?', ('static',)).fetchone()
            return json.loads(row[0]) if row else copy.deepcopy(static_analyzer.DEFAULT)

    def list(self):
        with self.lock, self.db() as c:
            runs = [json.loads(r[0]) for r in c.execute('SELECT body FROM demo_runs')]
        return [{k: r[k] for k in ('id', 'target', 'focus', 'status', 'revision', 'created', 'updated')} for r in sorted(runs, key=lambda r: r['created'], reverse=True)]

    def get(self, rid):
        with self.lock, self.db() as c:
            return self._load(c, rid)

    def knowledge(self):
        with self.lock, self.db() as c:
            return [json.loads(r[0]) for r in c.execute('SELECT body FROM expert_knowledge ORDER BY rowid DESC')]

    def _advance(self, c, run):
        stage = run.get('stages', STAGES)[run['stage']]
        if run.get('mode') == 'hybrid' and stage in ('investigate', 'plan', 'analyze', 'experiment', 'review', 'supplement', 'recheck'):
            self._start_model(c, run)
            return
        raise ValueError('旧模拟任务不能继续执行，请创建真实研究任务')

    def tick(self):
        with self.lock, self.db() as c:
            for row in c.execute('SELECT body FROM demo_runs').fetchall():
                run = json.loads(row[0])
                if run['status'] == 'running' and not run.get('active_job') and run['next_at'] <= time.time():
                    self._advance(c, run)
                    self._save(c, run)

    def _start_model(self, c, run):
        if run.get('active_job') or len(self._threads) >= 2 or self._closing.is_set():
            return
        token = uuid.uuid4().hex
        role = {'investigate': 'investigator', 'plan': 'planner', 'analyze': 'analyst', 'experiment':'experimenter', 'review':'reviewer', 'supplement':'analyst', 'recheck':'reviewer'}[run.get('stages', STAGES)[run['stage']]]
        run['knowledge_refs'] = self._confirmed_knowledge(c, run['id'])
        run['active_job'] = token
        run['roles'][role] = 'running'
        run.pop('error', None)
        self._event(run, role, '启动运行环境调查' if role == 'investigator' else '启动真实模型角色',
                    '内置采集器 · 自动定位启动配置和 ARM 进程，先查证基础事实' if role == 'investigator' else hybrid_agent.MODEL + ' · 后台执行，支持随时插话', source='system')
        snapshot = copy.deepcopy(run)
        thread = threading.Thread(target=self._model_job, args=(snapshot, token, role), daemon=True)
        self._threads[token] = thread
        # Caller commits the claim under this lock before the thread can publish.
        thread.start()

    def _model_job(self, snapshot, token, role):
        rid, revision, stage = snapshot['id'], snapshot['revision'], snapshot['stage']
        def valid(run):
            return (not self._closing.is_set() and run.get('active_job') == token
                    and run['revision'] == revision and run['stage'] == stage)
        def check():
            with self.lock, self.db() as c:
                if not valid(self._load(c, rid)): raise hybrid_agent.Superseded()
        def progress(title, detail):
            with self.lock, self.db() as c:
                run = self._load(c, rid)
                if not valid(run): raise hybrid_agent.Superseded()
                self._event(run, role, title, detail, source='tool' if title in ('采集静态证据', '运行环境调查') else 'system')
                self._save(c, run)
        workspace = self.data_root() / 'hybrid' / rid / f'r{revision}' / token
        try:
            check()
            workspace.mkdir(parents=True,exist_ok=True)
            if role == 'investigator' or (role == 'planner' and 'stages' not in snapshot):
                manifest = hybrid_agent.collect(snapshot['target'], workspace / 'inputs', check, progress)
                manifest_path = workspace / 'inputs/evidence.json'
            else:
                manifest_path = Path(snapshot['manifest_path'])
                manifest = json.loads(manifest_path.read_text())
            if role == 'investigator':
                investigation = runtime_probe.investigate(manifest['metadata']['resolved_binary'], manifest,
                                                          workspace / 'runtime', check, progress, hybrid_agent.execute)
                analysis = static_analyzer.collect(manifest, workspace / 'static-analysis', check, progress, hybrid_agent.execute, snapshot.get('static_tool_config'))
                graph = call_graph.collect(manifest, workspace / 'callgraph', check, progress, hybrid_agent.execute)
                manifest['call_graph'] = graph
                manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
                with self.lock, self.db() as c:
                    run = self._load(c, rid)
                    if not valid(run): return
                    run['manifest_path'] = str(manifest_path)
                    run['runtime_investigation'] = dict(investigation, revision=revision)
                    run['call_graph'] = dict(graph, revision=revision)
                    run['static_analysis'] = dict(analysis, revision=revision)
                    self._publish_evidence(run, manifest)
                    run['roles']['investigator'] = 'done'
                    run['roles']['planner'] = 'pending'
                    run['active_job'] = None
                    run['stage'] += 1
                    run['next_at'] = time.time() + 3
                    self._event(run, role, '基础调查已完成',
                                f"匹配 {len(investigation['launch_definitions'])} 项启动配置；采样 {len(investigation['processes'])} 个进程。基础事实与缺口自动交给规划 Agent。", source='tool')
                    self._save(c, run)
                return
            sandbox_profiles.collect(manifest, workspace/'profiles', check)
            stage_name=snapshot.get('stages', STAGES)[stage]
            if role=='experimenter' or stage_name=='supplement':
                verification_result=verification.collect(manifest,workspace/'verification',check,progress,hybrid_agent.execute)
                manifest_path=workspace/'evidence.json'
                manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
            context = {'goal': snapshot['focus'], 'target': snapshot['target'], 'revision': revision,
                       'expert_messages': snapshot['messages'], 'confirmed_knowledge': snapshot['knowledge_refs'],
                       'plan': snapshot['plan'], 'previous_results':[{'role':x['role'],'result':x['result']} for x in snapshot.get('model_results',[]) if x['revision']==revision], 'review_feedback':snapshot.get('reviews',[])[-1:], 'metadata': manifest['metadata'], 'runtime_investigation': manifest.get('runtime_investigation'), 'call_graph': manifest.get('call_graph'), 'static_analysis': {k: v for k, v in manifest.get('static_analysis', {}).items() if k != 'report'}}
            previous_ids={e['id'] for e in manifest['evidence']}
            outcome = hybrid_agent.run_role(role, context, manifest, workspace / role, check, progress)
            manifest_path=workspace/'evidence.json'
            manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
            with self.lock, self.db() as c:
                run = self._load(c, rid)
                if not valid(run): return
                for e in manifest['evidence']:
                    if e['id'] not in previous_ids:
                        self._artifact(run,'live_evidence',e['id']+' · '+e['title'],e['output'],source='tool')
                if role == 'planner':
                    run['manifest_path'] = str(manifest_path)
                    if 'stages' not in run: self._publish_evidence(run, manifest)
                    run['plan'] = outcome['result']['plan']
                run['manifest_path']=str(manifest_path)
                if role=='experimenter' or stage_name=='supplement':
                    if verification_result:
                        run['actual_verification']=dict(verification_result,revision=revision)
                    for e in manifest['evidence']:
                        if e['id'].startswith('V'):
                            self._artifact(run,'verification',e['title'],e['output'],source='tool')
                run.setdefault('model_results', []).append(dict(outcome, revision=revision, knowledge_refs=snapshot['knowledge_refs']))
                for tool_event in outcome.get('tool_events', []):
                    self._event(run, role, '模型实际工具调用', str(tool_event.get('command', ''))[:1500] + '\n退出码：' + str(tool_event.get('exit_code')), source='tool')
                self._artifact(run, 'model_analysis', {'planner':'真实规划','analyst':'真实静态分析','experimenter':'真实实验核验','reviewer':'真实证据评审'}[role] + ' · ' + hybrid_agent.MODEL,
                               json.dumps(outcome['result'], ensure_ascii=False, indent=2), source='model')
                run['roles'][role] = 'done'
                if role=='reviewer':
                    tasks=outcome['result'].get('task_results',[])
                    gaps=[t for t in tasks if t['status']=='blocked' or t['blocker'].strip()]
                    knowledge_gaps=[k for k in outcome['result'].get('knowledge_checks',[]) if k['status']=='blocked']
                    ready=bool(tasks) and not gaps and not knowledge_gaps and not outcome['result']['unknowns']
                    final=stage_name=='recheck'
                    status='ready_for_expert' if ready else 'research_blocked' if final else 'needs_analysis'
                    run['reviews'].append({'revision':revision,'status':status,'target':'expert' if ready else 'analyst',
                        'reason':outcome['result']['summary'],'acceptance':'逐项解决计划缺口；真实证据不足不得通过',
                        'refs':sorted({eid for t in tasks for eid in t['evidence_ids']}),'source':'model','gaps':gaps,'knowledge_gaps':knowledge_gaps})
                    if ready:
                        run['status']='waiting_expert';run['stage']=len(run.get('stages',STAGES))-1
                    elif final:run['status']='research_blocked'
                    else:run['roles']['analyst']='pending'
                elif role=='planner':run['roles']['analyst']='pending'
                elif role=='experimenter':run['roles']['reviewer']='pending'
                elif stage_name=='supplement':run['roles']['reviewer']='pending'
                else:run['roles']['experimenter']='pending'
                run['active_job'] = None
                run['stage'] += 1
                run['next_at'] = time.time() + 3
                self._event(run, role, '真实模型结果已保存', outcome['result']['summary'], source='model')
                self._save(c, run)
        except hybrid_agent.Superseded:
            pass
        except Exception as exc:
            with self.lock, self.db() as c:
                run = self._load(c, rid)
                if valid(run):
                    run['active_job'], run['status'], run['error'] = None, 'failed', str(exc)[:1200]
                    run['roles'][role] = 'failed'
                    self._event(run, role, '真实模型阶段失败', run['error'] + '；未回退为模拟结果，可恢复重试。', source='system')
                    self._save(c, run)
        finally:
            with self.lock:
                self._threads.pop(token, None)

    def _publish_evidence(self, run, manifest):
        for evidence in manifest['evidence']:
            content = json.dumps({k: v for k, v in evidence.items() if k != 'output'}, ensure_ascii=False, indent=2)
            content += '\n\n' + evidence['output'][:18000]
            if len(evidence['output']) > 18000: content += '\n[页面已截断；完整输出见记录路径]'
            self._artifact(run, 'runtime_evidence' if evidence['id'].startswith('R') else 'static_evidence',
                           evidence['id'] + ' · ' + evidence['title'], content, source='tool')

    def shutdown(self):
        self._closing.set()
        with self.lock:
            threads = list(self._threads.values())
        for thread in threads:
            thread.join(timeout=5)

    def action(self, rid, body):
        action = body.get('action')
        if action not in ('pause', 'resume', 'step', 'steer', 'note', 'close'):
            raise ValueError('未知操作')
        with self.lock, self.db() as c:
            run = self._load(c, rid)
            if run.get('mode')!='hybrid' and action in ('resume','step','steer'):
                raise ValueError('历史模拟任务不可继续，请新建真实 Luna 研究')
            if action in ('steer', 'note', 'close'):
                message = text_field(body, 'text')
                if action == 'close' and run['status'] != 'waiting_expert':
                    raise ValueError('请在评审完成后收束研究')
                if action == 'note' and run['status'] == 'completed':
                    raise ValueError('研究已收束，可通过调整方向开启新一轮')
                mid = 'M' + str(len(run['messages']) + 1)
                run['messages'].append({'id': mid, 'text': message, 'action': action, 'revision': run['revision'], 'time': time.time()})
                self._event(run, 'expert', {'steer': '专家调整方向', 'note': '专家补充经验', 'close': '专家收束研究'}[action], message, [mid])
                kid = uuid.uuid4().hex[:12]
                knowledge = {'id': kid, 'run_id': rid, 'message_id': mid, 'target': run['target'], 'original': message,
                             'summary': message, 'kind': '方向决策' if action == 'steer' else '阶段判断' if action == 'close' else '专家经验',
                             'scope': 'task', 'status': 'candidate', 'version': 1, 'history': [],
                             'created': time.time(), 'source': run['source'], 'evidence_status': '未经实验验证'}
                c.execute('INSERT INTO expert_knowledge VALUES (?,?)', (kid, json.dumps(knowledge, ensure_ascii=False)))
                run['roles']['knowledge'] = 'done'
                self._event(run, 'knowledge', '专家原话已归档', '候选知识保留原话，等待专家确认提炼和适用范围。', [kid, mid])
                if action == 'steer':
                    run['active_job'] = None
                    run['history'].append({k: copy.deepcopy(run[k]) for k in ('revision', 'focus', 'stage', 'status', 'plan', 'knowledge_refs')})
                    run['revision'] += 1
                    row = c.execute('SELECT body FROM tool_settings WHERE name=?', ('static',)).fetchone()
                    run['static_tool_config'] = json.loads(row[0]) if row else copy.deepcopy(static_analyzer.DEFAULT)
                    run['focus'], run['stage'], run['status'] = message, 0, 'running'
                    run['roles'] = {r: 'pending' for r in (['investigator', *ROLES] if 'stages' in run else ROLES)}
                    run.pop('dagger_analysis', None)
                    run.pop('static_analysis', None)
                    run.pop('call_graph', None)
                    run.pop('runtime_investigation', None)
                    run['roles']['knowledge'] = 'done'
                    run['plan'], run['knowledge_refs'], run['decision'] = [], [], None
                    run['next_at'] = time.time() + 2
                    self._event(run, 'planner', '开启新一轮计划', '旧轮次已归档；新方向按专家原话作为任务约束。')
                elif action == 'close':
                    run['status'], run['decision'] = 'completed', message
            elif action == 'pause':
                if run['status'] != 'running' and not run.get('active_job'): raise ValueError('只有执行中的研究可以暂停')
                run['status'] = 'paused'
                run['active_job'] = None
                self._event(run, 'expert', '暂停研究', '保留当前节点，等待恢复。')
            elif action == 'resume':
                if run['status'] not in ('paused', 'failed', 'research_blocked'): raise ValueError('只有暂停或失败的研究可以恢复')
                if run['status'] in ('failed','research_blocked') and 'stages' in run:
                    run['history'].append({k: copy.deepcopy(run[k]) for k in ('revision', 'focus', 'stage', 'status', 'plan', 'knowledge_refs')})
                    run['revision'] += 1
                    row = c.execute('SELECT body FROM tool_settings WHERE name=?', ('static',)).fetchone()
                    run['static_tool_config'] = json.loads(row[0]) if row else copy.deepcopy(static_analyzer.DEFAULT)
                    run['stage'] = 0
                    run['roles'] = {r: 'pending' for r in ['investigator', *ROLES]}
                    run['plan'], run['knowledge_refs'] = [], []
                    run.pop('dagger_analysis', None)
                    run.pop('static_analysis', None)
                    run.pop('call_graph', None)
                    run.pop('runtime_investigation', None)
                    run.pop('manifest_path', None)
                    run.pop('error', None)
                    self._event(run, 'investigator', '失败重试：重新调查环境', '旧证据与失败输出已保留；新轮次重新采样，避免复用过期或格式错误的证据。', source='system')
                run['status'], run['next_at'] = 'running', time.time() + 2
            elif action == 'step':
                if run.get('active_job'): raise ValueError('模型正在执行，可暂停或调整方向')
                if run['status'] not in ('running', 'paused'): raise ValueError('当前阶段等待专家决策')
                run['status'] = 'paused'
                self._advance(c, run)
            self._save(c, run)
            return run

    def _confirmed_knowledge(self, c, rid):
        entries = [json.loads(row[0]) for row in c.execute('SELECT body FROM expert_knowledge')]
        return [{key: k[key] for key in ('id', 'version', 'summary', 'original', 'scope')}
                for k in entries if k['status'] == 'confirmed' and k.get('source') == 'hybrid'
                and (k['scope'] == 'global' or k.get('run_id') == rid)]

    def create_knowledge(self, body):
        original = text_field(body, 'original')
        k = dict(id=uuid.uuid4().hex[:12], run_id=None, message_id=None, target='',
                 original=original, summary=original, kind='全局专家经验', scope='global',
                 status='confirmed', version=1, history=[], created=time.time(), source='hybrid',
                 evidence_status='方法待各 Agent 按目标验证')
        with self.lock, self.db() as c:
            c.execute('INSERT INTO expert_knowledge VALUES (?,?)', (k['id'], json.dumps(k, ensure_ascii=False)))
        return k

    def edit_knowledge(self, kid, body):
        summary = text_field(body, 'summary')
        status, scope = body.get('status'), body.get('scope')
        if status not in ('candidate', 'confirmed', 'retired') or scope not in ('task', 'global'):
            raise ValueError('知识状态或范围无效')
        with self.lock, self.db() as c:
            row = c.execute('SELECT body FROM expert_knowledge WHERE id=?', (kid,)).fetchone()
            if not row: raise ValueError('知识不存在')
            k = json.loads(row[0])
            if not k.get('run_id') and scope != 'global': raise ValueError('独立专家经验只能使用全局范围')
            if body.get('version') != k['version']: raise ValueError('知识已被更新，请刷新后重试')
            k['history'].append({key: k[key] for key in ('version', 'summary', 'status', 'scope')})
            k.update(summary=summary, status=status, scope=scope, version=k['version'] + 1)
            c.execute('UPDATE expert_knowledge SET body=? WHERE id=?', (json.dumps(k, ensure_ascii=False), kid))
            return k
