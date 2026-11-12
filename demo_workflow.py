"""Persistent simulated or hybrid multi-agent research workflows."""
import copy
import json
import threading
import hybrid_agent
import runtime_probe
import call_graph
import static_analyzer
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
                              'detail': detail, 'refs': refs or [], 'source': source or ('expert' if role == 'expert' else 'simulation')})

    def _artifact(self, run, kind, title, content, source="simulation"):
        artifact = {'id': 'E' + str(len(run['artifacts']) + 1), 'revision': run['revision'],
                    'kind': kind, 'title': title, 'content': content, 'source': source,
                    'focus': run['focus'], 'target': run['target']}
        run['artifacts'].append(artifact)
        return artifact['id']

    def create(self, body):
        target = text_field(body, 'target', 4096).rstrip('/')
        mode = body.get('mode', 'simulation')
        if mode not in ('simulation', 'hybrid'): raise ValueError('不支持的研究模式')
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
               'source': 'hybrid' if mode == 'hybrid' else 'simulation', 'mode': mode,
               'model': hybrid_agent.MODEL if mode == 'hybrid' else None, 'active_job': None, 'model_results': [], 'decision': None}
        if mode == 'hybrid':
            run['stages'] = ['investigate', *STAGES]
            run['roles'] = {'investigator': 'pending', **run['roles']}
        self._event(run, 'planner', '研究已创建', '默认先自动调查运行身份、权限、sandbox 与 IPC，再由 gpt-6-luna 规划分析；漏洞实验仍模拟。' if mode == 'hybrid' else '输入仅作为目标标识；不会读取内容、运行或分析该目标。', source='system')
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
        if run.get('mode') == 'hybrid' and stage in ('investigate', 'plan', 'analyze'):
            self._start_model(c, run)
            return
        focus = run['focus']
        binary = run.get('scenario', 'xpc') == 'input-boundary'
        if stage == 'plan':
            candidates = [json.loads(r[0]) for r in c.execute('SELECT body FROM expert_knowledge')]
            refs = [k for k in candidates if k['status'] == 'confirmed' and k.get('source', 'simulation') == run['source'] and (k['scope'] == 'global' or k['run_id'] == run['id'])]
            run['knowledge_refs'] = [{'id': k['id'], 'version': k['version'], 'summary': k['summary']} for k in refs]
            run['plan'] = [f'分析：围绕「{focus}」列出入口与未知项', '实验：固定环境，记录正常、空和截断输入的返回值' if binary else '实验：记录身份、配置和返回值', '评审：检查证据引用与对照完整性', '专家：判断方向、价值与阶段结论']
            run['roles']['planner'] = 'done'
            run['roles']['analyst'] = 'running'
            self._event(run, 'planner', '计划已拆解', '\n'.join(run['plan']) + f'\n引用 {len(refs)} 条已确认的演示知识。', [k['id'] for k in refs])
        elif stage == 'analyze':
            eid = self._artifact(run, 'observation', '模拟分析记录 · 入口与未知项', (f'研究方向：{focus}\n预设模型包含输入接收 → 格式检查 → 结果返回。待验证：空输入和截断输入的处理。\n此记录来自通用输入边界演示夹具，未确认目标的实际调用结构。' if binary else f'研究方向：{focus}\n预设模型包含 client → broker → service 三段调用。转发后的身份来源尚未验证。\n此记录来自演示夹具，不是对目标二进制的发现。'))
            run['roles']['analyst'] = 'done'
            run['roles']['experimenter'] = 'running'
            self._event(run, 'analyst', '分析材料交给实验 Agent', '已列出输入边界处理这一未知项，准备对照验证。' if binary else '已列出身份来源这一未知项，准备对照验证。', [eid])
        elif stage == 'experiment':
            eid = self._artifact(run, 'experiment', '模拟实验 01 · 基线', (f'研究方向：{focus}\nfixture=input-boundary-v1; config=A; input=normal; result=accepted\n缺口：尚未覆盖空输入和截断输入。没有实际执行命令。' if binary else f'研究方向：{focus}\nfixture=xpc-demo-v1; config=A; caller=administrator; response=accepted\n缺口：尚未覆盖普通用户。没有实际执行命令。'))
            run['roles']['experimenter'] = 'done'
            run['roles']['reviewer'] = 'running'
            self._event(run, 'experimenter', '提交首次实验记录', '预设基线已返回；结果待评审。', [eid])
        elif stage == 'review':
            refs = [a['id'] for a in run['artifacts'] if a['revision'] == run['revision']]
            review = {'revision': run['revision'], 'status': 'needs_experiment', 'target': 'experimenter',
                      'reason': '当前只有正常输入，缺少空输入和截断输入，不能判断边界处理。' if binary else '当前只有管理员身份，无法比较低权限调用者的行为。',
                      'acceptance': '固定 config=A，补充空输入和截断输入，记录输入条件、返回值及异常。' if binary else '固定 config=A，增加普通用户对照，保留身份与返回值。', 'refs': refs}
            run['reviews'].append(review)
            run['roles']['reviewer'] = 'returned'
            run['roles']['experimenter'] = 'running'
            self._event(run, 'reviewer', '评审打回 → 补充实验', review['reason'] + '\n补齐标准：' + review['acceptance'], refs)
        elif stage == 'supplement':
            eid = self._artifact(run, 'experiment', '模拟实验 02 · 补充对照', (f'研究方向：{focus}\nfixture=input-boundary-v1; config=A\ninput=normal; result=accepted\ninput=empty; result=rejected\ninput=truncated; result=rejected\n以上均为预设数据，未执行目标，也没有验证其真实行为。' if binary else f'研究方向：{focus}\nfixture=xpc-demo-v1; config=A\ncaller=administrator; response=accepted\ncaller=standard-user; response=denied\n仅为预设对照数据，不代表目标的真实权限行为。'))
            run['roles']['experimenter'] = 'done'
            run['roles']['reviewer'] = 'running'
            self._event(run, 'experimenter', '已补齐评审要求', '使用相同配置补充空输入与截断输入，重新提交评审。' if binary else '使用相同配置补充普通用户对照，重新提交评审。', [eid])
        else:
            refs = [a['id'] for a in run['artifacts'] if a['revision'] == run['revision']]
            run['reviews'].append({'revision': run['revision'], 'status': 'ready_for_expert', 'target': 'expert',
                                   'reason': '模拟对照记录已完整；研究价值和安全结论等待专家判断。', 'acceptance': '请专家选择继续研究或收束，并留下判断。', 'refs': refs})
            run['roles']['reviewer'] = 'done'
            run['status'] = 'waiting_expert'
            self._event(run, 'reviewer', '提交专家判断', '可陈述：预设正常输入被接受，空输入和截断输入被拒绝。未知：实际目标的调用入口、输入格式和处理行为。请专家判断下一步。' if binary else '可陈述：两种身份在预设数据中返回不同结果。未知：实际目标行为。请专家判断下一步。', refs)
        run['stage'] += 1
        run['next_at'] = time.time() + 3

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
        role = {'investigate': 'investigator', 'plan': 'planner', 'analyze': 'analyst'}[run.get('stages', STAGES)[run['stage']]]
        if role == 'planner':
            entries = [json.loads(row[0]) for row in c.execute('SELECT body FROM expert_knowledge')]
            run['knowledge_refs'] = [{'id': k['id'], 'version': k['version'], 'summary': k['summary']}
                                     for k in entries if k['status'] == 'confirmed' and k.get('source') == 'hybrid'
                                     and (k['scope'] == 'global' or k['run_id'] == run['id'])]
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
            context = {'goal': snapshot['focus'], 'target': snapshot['target'], 'revision': revision,
                       'expert_messages': snapshot['messages'], 'confirmed_knowledge': snapshot['knowledge_refs'],
                       'plan': snapshot['plan'], 'metadata': manifest['metadata'], 'runtime_investigation': manifest.get('runtime_investigation'), 'call_graph': manifest.get('call_graph'), 'static_analysis': {k: v for k, v in manifest.get('static_analysis', {}).items() if k != 'report'}}
            outcome = hybrid_agent.run_role(role, context, manifest, workspace / role, check, progress)
            with self.lock, self.db() as c:
                run = self._load(c, rid)
                if not valid(run): return
                if role == 'planner':
                    run['manifest_path'] = str(manifest_path)
                    if 'stages' not in run: self._publish_evidence(run, manifest)
                    run['plan'] = outcome['result']['plan']
                run.setdefault('model_results', []).append(dict(outcome, revision=revision))
                for tool_event in outcome.get('tool_events', []):
                    self._event(run, role, '模型实际工具调用', str(tool_event.get('command', ''))[:1500] + '\n退出码：' + str(tool_event.get('exit_code')), source='tool')
                self._artifact(run, 'model_analysis', ('真实规划' if role == 'planner' else '真实静态分析') + ' · ' + hybrid_agent.MODEL,
                               json.dumps(outcome['result'], ensure_ascii=False, indent=2), source='model')
                run['roles'][role] = 'done'
                run['roles']['analyst' if role == 'planner' else 'experimenter'] = 'pending'
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
                if run['status'] not in ('paused', 'failed'): raise ValueError('只有暂停或失败的研究可以恢复')
                if run['status'] == 'failed' and 'stages' in run:
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

    def edit_knowledge(self, kid, body):
        summary = text_field(body, 'summary')
        status, scope = body.get('status'), body.get('scope')
        if status not in ('candidate', 'confirmed', 'retired') or scope not in ('task', 'global'):
            raise ValueError('知识状态或范围无效')
        with self.lock, self.db() as c:
            row = c.execute('SELECT body FROM expert_knowledge WHERE id=?', (kid,)).fetchone()
            if not row: raise ValueError('知识不存在')
            k = json.loads(row[0])
            if body.get('version') != k['version']: raise ValueError('知识已被更新，请刷新后重试')
            k['history'].append({key: k[key] for key in ('version', 'summary', 'status', 'scope')})
            k.update(summary=summary, status=status, scope=scope, version=k['version'] + 1)
            c.execute('UPDATE expert_knowledge SET body=? WHERE id=?', (json.dumps(k, ensure_ascii=False), kid))
            return k
