const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const roleNames = {investigator:'环境调查 Agent',planner:'规划 Agent',analyst:'分析 Agent',experimenter:'实验 Agent',reviewer:'评审 Agent',knowledge:'知识 Agent',expert:'人类专家'};
const states = {running:'研究中',paused:'已暂停',waiting_expert:'等待专家判断',completed:'已收束',failed:'阶段失败 · 可重试'};
const sources = {simulation:'模拟数据',hybrid:'真实规划分析 · 实验模拟',expert:'专家输入',tool:'真实工具记录',model:'真实模型 · gpt-6-luna',system:'编排记录'};
const roleStates = {pending:'等待交接',running:'正在处理',done:'已交付',returned:'已退回 · 等待补齐',failed:'调用失败'};
let selected = localStorage.getItem('nexus-demo-selected'), run = null, knowledge = [], busy = false, mutating = false, view = 'research', lastRendered = '', mutationEpoch = 0;
async function api(path, body) {
  const response = await fetch(path, body === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw Error(data.error || '请求失败');
  return data;
}
function fail(error) { $('error').textContent = error.message; $('error').hidden = false; }
function notify(message) { $('notice').textContent = message; $('notice').hidden = false; }
async function perform(fn) {
  if (mutating) return;
  mutating = true; mutationEpoch += 1; $('error').hidden = true;
  const buttons = [...document.querySelectorAll('button')]; buttons.forEach(b => b.disabled = true);
  try { await fn(); } catch(e) { fail(e); }
  finally { mutating = false; buttons.forEach(b => b.disabled = false); if(run) render(run); }
}
function setView(next) {
  view = next; $('researchView').hidden = next !== 'research'; $('knowledgeView').hidden = next !== 'knowledge';
  $('researchTab').classList.toggle('active', next === 'research'); $('knowledgeTab').classList.toggle('active', next === 'knowledge');
  $('pageTitle').textContent = next === 'research' ? '研究工作台' : '专家知识库';
}
async function choose(id) {
  selected = id; localStorage.setItem('nexus-demo-selected', id); lastRendered = ''; setView('research');
  $('createPanel').open = false; $('expertText').value = ''; await refresh();
}
async function refresh() {
  if (busy || mutating) return; busy = true;
  const requested = selected, epoch = mutationEpoch;
  try {
    const list = await api('/api/demo/runs');
    $('runs').innerHTML = list.map(r => `<button class="run-item ${r.id===selected?'active':''}" data-run="${r.id}">${esc(r.target.split('/').pop())}<small>第 ${r.revision} 轮 · ${esc(states[r.status])}</small></button>`).join('') || '<p class="empty-note">还没有研究任务</p>';
    if (requested) {
      if (!list.some(r => r.id === requested)) { selected = null; localStorage.removeItem('nexus-demo-selected'); run = null; $('runDetail').hidden = true; $('welcome').hidden = false; return; }
      const result = await api('/api/demo/runs/' + requested);
      if (selected !== requested || epoch !== mutationEpoch || mutating) return;
      run = result;
      const fingerprint = JSON.stringify(result);
      if (fingerprint !== lastRendered) { render(result); lastRendered = fingerprint; }
    }
  } catch(e) { fail(e); } finally { busy = false; }
}
function render(r) {
  $('welcome').hidden = true; $('runDetail').hidden = false;
  $('runId').textContent = 'RESEARCH / ' + r.id;
  $('targetName').textContent = r.target.split('/').pop(); $('targetPath').textContent = r.target;
  $('runStatus').textContent = states[r.status]; $('roundLabel').textContent = `第 ${r.revision} 轮 · 已完成 ${r.stage} / ${(r.stages || Array(6)).length} 个流程节点`;
  $('pause').textContent = r.active_job ? '暂停当前调查/调用' : ['paused','failed'].includes(r.status) ? '继续执行' : '暂停';
  $('pause').disabled = !['running','paused','failed'].includes(r.status); $('step').disabled = !!r.active_job || !['running','paused'].includes(r.status);
  $('expertAction').querySelector('[value="close"]').disabled = r.status !== 'waiting_expert';
  $('expertAction').querySelector('[value="note"]').disabled = r.status === 'completed';
  if ($('expertAction').selectedOptions[0].disabled) $('expertAction').value = 'steer';
  updateHint();
  $('workflow').innerHTML = Object.entries(r.roles).map(([role,status],i) => `<div class="agent ${esc(status)}"><span class="num">0${i+1} / ${esc(role.toUpperCase())}</span><strong>${roleNames[role]}</strong><small>${roleStates[status]}</small></div>`).join('');
  $('executionMode').textContent = sources[r.source] || r.source;
  renderRuntime(r);
  renderCallGraph(r);
  const dagger=r.static_analysis || r.dagger_analysis;
  $('staticAnalysisPanel').hidden=!dagger;
  if(dagger){
    $('staticAnalysisStatus').textContent=({executed:'命令执行完成 · 覆盖范围需核对报告',disabled:'未启用外部静态分析工具',completed:'引擎执行完成',incomplete:'分析不完整',failed:'引擎执行失败',timeout:'超时',unavailable:'引擎不可用',invalid_output:'输出无效'}[dagger.status]||dagger.status)+' · 不代表已确认漏洞或安全';
    $('staticAnalysisResult').textContent=JSON.stringify(dagger,null,2);
  }
  renderModel(r);
  $('focus').textContent = r.focus;
  $('plan').innerHTML = r.plan.map(p => `<li>${esc(p)}</li>`).join('') || '<li>规划 Agent 即将按专家方向拆解任务。</li>';
  $('knowledgeRefs').textContent = r.knowledge_refs.length ? '本轮引用：' + r.knowledge_refs.map(k => `${k.id} v${k.version} · ${k.summary}`).join('；') : '本轮暂无已确认知识引用。';
  const reviews = r.reviews.filter(x => x.revision === r.revision);
  $('reviewCount').textContent = `${reviews.length} 次评审`;
  $('reviews').innerHTML = reviews.map(x => `<div class="review-card ${x.status==='ready_for_expert'?'pass':''}"><strong>${x.status==='ready_for_expert'?'✓ 材料就绪 → 专家判断':'↩ 评审打回 → 实验 Agent'}</strong><p>${esc(x.reason)}</p><small>补齐标准：${esc(x.acceptance)}</small><small>引用：${esc(x.refs.join(' · '))}</small></div>`).join('') || '<p class="empty-note">等待分析与实验提交材料。</p>';
  renderArtifacts();
  $('timeline').innerHTML = [...r.events].reverse().map(e => `<div class="event ${e.role==='expert'?'expert':''}"><small>第 ${e.revision} 轮 · ${roleNames[e.role]} · ${new Date(e.time*1000).toLocaleTimeString()} · ${esc(sources[e.source] || e.source)}</small><br><strong>${esc(e.title)}</strong><p>${esc(e.detail)}</p>${e.refs.length?`<small>关联 ${esc(e.refs.join(' · '))}</small>`:''}</div>`).join('');
  $('messages').innerHTML = [...r.messages].reverse().map(m => `<div class="message"><small>${esc(m.id)} · 第 ${m.revision} 轮 · 专家原话</small><p>${esc(m.text)}</p></div>`).join('') || '<p class="empty-note">你的发言会在这里保留。</p>';
  $('history').innerHTML = r.history.map(h => `<details class="artifact"><summary>第 ${h.revision} 轮 · 已归档 · ${esc(h.focus)}</summary><p class="muted">归档时：${esc(states[h.status])}；已执行 ${h.stage} 个节点</p><ol>${h.plan.map(p=>`<li>${esc(p)}</li>`).join('')}</ol></details>`).join('') || '<p class="empty-note">调整方向后，旧计划将在此归档。</p>';
  $('decision').innerHTML = r.decision ? `<div class="decision"><strong>专家阶段判断</strong><p>${esc(r.decision)}</p></div>` : '';
}
function renderRuntime(r) {
  $('runtimePanel').hidden = !r.stages;
  const v = r.runtime_investigation;
  $('runtimeStatus').textContent = v ? '基础事实自动查证；只在证据支持的采样范围内下结论。' : '先定位真实启动链与进程，再采集 UID、entitlements、sandbox 和 IPC。';
  $('runtimeResults').innerHTML = !v ? '' : v.processes.map(p=>{
    const sample = p.followup || p, i = sample.identity, e = sample.entitlements, b = sample.sandbox;
    return `<div class="message"><strong>PID ${i.pid} · UID ${i.uid} / EUID ${i.euid} · PPID ${i.ppid}</strong><p>${esc(new Date(sample.observed_at*1000).toLocaleString())} · ${esc(p.evidence_id)}</p><p>Sandbox：${b.status==='confirmed' ? (b.sandboxed?'已启用':'采样时未启用') : '查询失败，未知'}</p><small>${esc(b.scope)}</small><p>运行时 Entitlements：${esc(e.status)}</p><pre>${esc(JSON.stringify(e.values || e,null,2))}</pre></div>`;
  }).join('') + `<h3>IPC 注册及入口线索</h3><pre>${esc(JSON.stringify(v.ipc,null,2))}</pre><details><summary>采集范围与技术限制</summary><ul>${v.limitations.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></details>`;
}
function renderCallGraph(r) {
  const g=r.call_graph;
  $('callGraphPanel').hidden=!g;
  if(!g)return;
  $('callGraphStatus').textContent=g.status==='collected' ? `${g.engine} · ${g.function_count} 个函数 · ${g.edge_count} 条调用边 · ${g.unresolved_call_count} 个未解析间接调用。以下是静态路径，不代表已验证漏洞。` : g.error;
  $('callGraphResults').innerHTML=(g.findings||[]).map(f=>`<details class="artifact"><summary>#${f.finding_idx} · ${esc(f.tag)} · ${f.hops} 跳 → ${esc(f.sink)} · UNVERIFIED</summary><p>${esc(f.chain)}</p><small>入口依据：${esc(f.source_reason)}</small><pre>${esc(JSON.stringify(f.edges,null,2))}</pre><small>逐跳反汇编：${esc(f.disasm_file)}</small></details>`).join('') + `<p class="muted">${esc(g.path_policy||'')} ${g.truncated?'达到搜索上限，结果不完整。':''}</p><small>导出：${esc(g.findings_path||'')}</small>`;
}
function renderModel(r) {
  $('modelPanel').hidden = r.mode !== 'hybrid';
  $('modelStatus').textContent = r.error || (r.active_job ? (r.roles.investigator==='running' ? '正在自动调查运行环境与 IPC，完成后进入模型规划。' : 'gpt-6-luna 正在后台工作。可暂停或随时调整方向，日志见研究时间线。') : '引用片段已校验；模型解释与研究价值仍需专家判断。实验保持模拟。');
  $('modelResults').innerHTML = (r.model_results || []).filter(m=>m.revision===r.revision).map(m=>`<details class="artifact" open><summary>${esc(roleNames[m.role])} · ${esc(m.model)} · ${m.duration_seconds}s</summary><p>${esc(m.result.summary)}</p><h3>有引用的观察</h3>${m.result.observations.map(o=>`<div class="message"><p>${esc(o.statement)}</p><small>${esc(o.evidence_id)} · 原文引用</small><pre>${esc(o.quote)}</pre></div>`).join('')}<h3>模型推断与限制</h3>${m.result.inferences.map(i=>`<div class="message"><p>${esc(i.statement)}</p><small>${esc(i.evidence_ids.join(', '))} · ${esc(i.limitation)}</small></div>`).join('')}<h3>尚未确认</h3><ul>${m.result.unknowns.map(x=>`<li>${esc(x)}</li>`).join('')}</ul><h3>后续研究建议</h3><ul>${m.result.expert_questions.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>${m.attempts ? `<p>已自动纠错一次；首次输出未通过引用校验，以下为通过校验的结果。</p>${m.attempts.map(a=>`<small>${a.accepted ? "通过" : "未通过"} · ${esc(a.result_path)}</small>`).join("<br>")}` : ""}<small>原始记录：${esc(m.events_path)}</small></details>`).join('');
}
function renderArtifacts() {
  if (!run) return;
  const items = run.artifacts.filter(a => $('allArtifacts').checked || a.revision === run.revision);
  const opened = new Set([...$('artifacts').querySelectorAll('details[open]')].map(d=>d.dataset.evidence));
  $('artifacts').innerHTML = items.map(a => `<details class="artifact" data-evidence="${a.id}" ${opened.has(a.id)?'open':''}><summary>${esc(a.id)} · ${esc(a.title)} <small>第 ${a.revision} 轮</small></summary><pre>${esc(a.content)}</pre><small>来源：${esc(sources[a.source] || a.source)} · 目标标识 ${esc(a.target)}</small></details>`).join('') || '<p class="empty-note">本轮尚未生成材料。</p>';
}
function updateHint() {
  $('actionHint').textContent = {steer:'归档旧计划，以你的原话开启新一轮。',note:'只归档经验，不改变本轮研究方向。',close:'保留你的阶段判断并结束本轮自动执行。'}[$('expertAction').value];
}
async function loadKnowledge() {
  knowledge = await api('/api/demo/knowledge'); $('knowledgeCount').textContent = knowledge.length; renderKnowledge();
}
function renderKnowledge() {
  const query = $('knowledgeSearch').value.toLowerCase();
  const items = knowledge.filter(k => [k.original,k.summary,k.target].join(' ').toLowerCase().includes(query));
  $('knowledgeList').innerHTML = items.map(k => `<article class="panel knowledge-card" data-knowledge="${k.id}"><div class="section-title"><h3>${esc(k.kind)} · ${esc(k.id.slice(0,6))}</h3><span class="badge ${k.status==='confirmed'?'':'amber'}">${{candidate:'待专家确认',confirmed:'专家已确认',retired:'已废弃'}[k.status]} · v${k.version}</span></div><div class="knowledge-meta"><small>${esc(sources[k.source] || k.source)} · 原话 ${esc(k.message_id)} · ${new Date(k.created*1000).toLocaleString()}</small><button class="secondary source-run" data-run="${k.run_id}">查看来源研究 ↗</button></div><p class="path">${esc(k.target)}</p><blockquote>${esc(k.original)}</blockquote><form class="knowledge-form"><label>可编辑的知识提炼<textarea aria-label="可编辑的知识提炼" name="summary" maxlength="2000" required rows="3">${esc(k.summary)}</textarea></label><div class="knowledge-actions"><label>适用范围<select name="scope"><option value="task" ${k.scope==='task'?'selected':''}>仅当前研究</option><option value="global" ${k.scope==='global'?'selected':''}>同模式全部研究</option></select></label><label>确认状态<select name="status"><option value="candidate" ${k.status==='candidate'?'selected':''}>待确认</option><option value="confirmed" ${k.status==='confirmed'?'selected':''}>专家确认</option><option value="retired" ${k.status==='retired'?'selected':''}>废弃</option></select></label><button type="submit">保存知识</button></div></form><small>未经实验验证。确认的条目会在下一次规划时检索引用。</small><details class="knowledge-history"><summary>修订历史 · ${k.history.length} 条</summary>${k.history.map(h=>`<p>v${h.version} · ${esc(h.status)} · ${esc(h.scope)}<br>${esc(h.summary)}</p>`).join('')||'<p>尚无修订。</p>'}</details></article>`).join('') || '<div class="panel empty-note">暂无匹配知识。在研究中提交专家意见后，原话会自动归档到这里。</div>';
}
$('createForm').onsubmit = e => {e.preventDefault(); perform(async()=>{
  run = await api('/api/demo/runs',{target:$('target').value,goal:$('goal').value,mode:$('runMode').value}); selected=run.id; localStorage.setItem('nexus-demo-selected',selected);
  $('createPanel').open=false; $('expertText').value=''; render(run); lastRendered=''; notify('研究已启动。你可以随时暂停、单步推进或插话。');
});};
$('sample').onclick=()=>{$('runMode').value='simulation';$('target').value='/System/Library/XPCServices/DemoIdentityService.xpc';$('goal').value='检查代理转发后的调用者身份与权限边界';};
$('newRun').onclick=()=>{setView('research');$('createPanel').open=true;$('target').focus();};
$('runs').onclick=e=>{const b=e.target.closest('[data-run]');if(b) choose(b.dataset.run).catch(fail);};
$('researchTab').onclick=()=>setView('research');
$('knowledgeTab').onclick=()=>{setView('knowledge');loadKnowledge().catch(fail);};
$('knowledgeSearch').oninput=renderKnowledge;
$('expertAction').onchange=updateHint;
$('allArtifacts').onchange=renderArtifacts;
$('expertForm').onsubmit=e=>{e.preventDefault();if(!selected)return;perform(async()=>{
  run=await api(`/api/demo/runs/${selected}/action`,{action:$('expertAction').value,text:$('expertText').value}); $('expertText').value='';render(run);lastRendered='';
  await loadKnowledge();notify('专家意见已记录，知识候选已归档。');
});};
for(const id of ['pause','step']) $(id).onclick=()=>perform(async()=>{
  run=await api(`/api/demo/runs/${selected}/action`,{action:id==='step'?'step':run.active_job?'pause':['paused','failed'].includes(run.status)?'resume':'pause'});render(run);lastRendered='';
});
$('knowledgeList').onclick=e=>{const b=e.target.closest('.source-run');if(b)choose(b.dataset.run).catch(fail);};
$('knowledgeList').onsubmit=e=>{if(!e.target.matches('.knowledge-form'))return;e.preventDefault();const form=e.target;const id=form.closest('[data-knowledge]').dataset.knowledge;const k=knowledge.find(x=>x.id===id);perform(async()=>{
  await api('/api/demo/knowledge/'+id,{summary:form.elements.summary.value,status:form.elements.status.value,scope:form.elements.scope.value,version:k.version});await loadKnowledge();notify('知识已保存。原话保持可追溯，下一轮规划使用确认后的版本。');
});};
$('exportRun').onclick=()=>{if(!run)return;const blob=new Blob([JSON.stringify(run,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`ssj-${run.id}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
refresh();loadKnowledge().catch(fail);setInterval(refresh,1000);

async function loadStaticTool() {
  const c=await api('/api/demo/static-tool');
  $('toolEnabled').checked=c.enabled;$('toolName').value=c.name;$('toolExecutable').value=c.executable;
  $('toolArgs').value=JSON.stringify(c.args,null,2);$('toolFormat').value=c.format;
  $('toolOutput').value=c.output;$('toolTimeout').value=c.timeout_seconds;
}
$('staticToolForm').onsubmit=e=>{e.preventDefault();perform(async()=>{
  await api('/api/demo/static-tool',{enabled:$('toolEnabled').checked,name:$('toolName').value,
    executable:$('toolExecutable').value,args:JSON.parse($('toolArgs').value),format:$('toolFormat').value,
    output:$('toolOutput').value,timeout_seconds:Number($('toolTimeout').value)});
  $('toolSaved').textContent='已保存 · 新任务 / 新轮次生效';
});};
loadStaticTool().catch(fail);
