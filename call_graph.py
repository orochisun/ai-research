"""Evidence-backed ARM callgraph and bounded IPC-source-to-sink paths."""
from collections import defaultdict, deque
import hashlib
import json
import os
from pathlib import Path
import shutil
import platform

SINKS = {'_sandbox_extension_issue_file':'sink:capability', '_SecKeychainGetPath':'sink:path', '_xpc_connection_send_message':'sink:reply', '_compression_decode_buffer':'sink:extract', '_uncompress':'sink:extract',
         '_open':'sink:file', '_openat':'sink:file', '_write':'sink:file', '_writev':'sink:file',
         '_fopen':'sink:file', '_mmap':'sink:memory', '_memcpy':'sink:memory',
         '_CFPropertyListCreateFromXMLData':'sink:parse', '_CFPropertyListCreateWithData':'sink:parse',
         '_ATSFontValidate':'sink:validate', '_sandbox_consume_extension':'sink:capability',
         '_sandbox_extension_consume':'sink:capability', '_SecTaskCopyValueForEntitlement':'sink:auth'}


def find_paths(graph, target, folder, max_depth=12, max_findings=100, max_visits=10000):
    folder.mkdir(parents=True,exist_ok=True)
    nodes=graph['nodes'];outgoing=defaultdict(list)
    for edge in graph['edges']:
        if edge['kind'] in ('direct_call','tail_call','resolved_register_call'):
            outgoing[edge['from']].append(edge)
    findings=[];limited=False;visits=0
    for source in graph['sources']:
        queue=deque([(source['address'],[],[source['address']])]);seen=set()
        while queue:
            address,edges,chain=queue.popleft();visits+=1
            if visits>max_visits or len(findings)>=max_findings:limited=True;break
            if address in seen:continue
            seen.add(address);node=nodes[address]
            if edges and node['name'] in SINKS:
                idx=len(findings)+1
                names=[nodes[x]['display'] for x in chain]
                chain_text=' -> '.join(names)
                disasm=folder/f'{idx}.txt'
                parts=[]
                for edge in edges:
                    parts.append(json.dumps(edge,ensure_ascii=False))
                    parts.append('\n'.join(nodes[edge['from']]['disassembly']))
                disasm.write_text('\n\n'.join(parts))
                tag=SINKS[node['name']]
                findings.append({'finding_idx':idx,'source':names[0],'sink':node['name'],'tag':tag,'chain':chain_text,
                                 'source_reason':source['source_reason'],'hops':len(edges),'edges':edges,
                                 'raw':f'#{idx}|{target}|{names[0]}|{node["name"]}|{tag}|{len(edges)}|{chain_text}|REASON:{source["source_reason"]}|UNVERIFIED',
                                 'disasm_file':str(disasm),'status':'UNVERIFIED',
                                 'meaning':'静态调用链；未证明分支可行、输入可控或漏洞。'})
            if node.get('external'):continue
            if len(edges)>=max_depth:
                if outgoing[address]:limited=True
                continue
            for edge in outgoing[address]:
                if edge['to'] in nodes and edge['to'] not in chain:
                    queue.append((edge['to'],edges+[edge],chain+[edge['to']]))
        if visits>max_visits or len(findings)>=max_findings:break
    return {'findings':findings,'truncated':limited,'limits':{'max_depth':max_depth,'max_findings':max_findings,'max_visits':max_visits},
            'path_policy':'One shortest discovered path per source/sink; not all paths.',
            'unresolved_calls':graph.get('unresolved_calls',[]),'sources':graph['sources'],
            'limitations':graph.get('limitations',[])}


def ida_python():
    configured=os.environ.get('SSJ_IDA_PYTHON')
    if configured:return Path(configured).expanduser()
    root=Path(os.environ.get('CODEX_HOME',str(Path.home()/'.codex')))
    choices=sorted((root/'plugins/cache/mrexodia/ida-pro-mcp').glob('*/.venv/bin/python3'))
    return choices[-1] if choices else None


def collect(manifest, folder, check, progress, execute):
    folder.mkdir(parents=True,exist_ok=True);check()
    manifest['evidence'] = [e for e in manifest['evidence'] if not e['id'].startswith('C')]
    python=ida_python()
    if not python or not python.is_file():
        return {'status':'unavailable','error':'未找到 IDAPython；设置 SSJ_IDA_PYTHON。不能把未生成的调用链标为通过。'}
    # The collector's already selected ARM-only snapshot, copied to an owned IDA workspace.
    source=Path(next(e['argv'][-1] for e in manifest['evidence'] if e['id']=='T1'))
    raw=source.read_bytes()
    from binary_policy import select_arm
    selected,selection=select_arm(raw)
    if selected!=raw or hashlib.sha256(raw).hexdigest()!=manifest['metadata']['sha256']:
        raise ValueError('调用图输入不是匹配的 thin ARM 快照')
    binary=folder/'target.arm';binary.write_bytes(raw);binary.chmod(0o400)
    export=folder/'ida-export.json'
    progress('运行环境调查','IDA 自动恢复 IPC 回调、调用边与鉴权控制流')
    code,duration=execute([str(python),str(Path(__file__).parent/'tools/ida_export.py'),str(binary),str(export)],
                          folder,folder/'ida.stdout',folder/'ida.stderr',check,180)
    if code:raise RuntimeError(f'IDA 调用图失败，退出码 {code}，日志：{folder / "ida.stderr"}')
    graph=json.loads(export.read_text());check()
    paths=find_paths(graph,manifest['metadata']['target'],folder/'disasm')
    (folder/'findings.json').write_text(json.dumps(paths,ensure_ascii=False,indent=2))
    summary={k:v for k,v in paths.items() if k!='unresolved_calls'}
    summary.update(detail_coverage=graph.get('detail_coverage',{}),status='collected',engine=graph['engine'],architecture=selection['architecture'],sha256=manifest['metadata']['sha256'],
                   function_count=len(graph['nodes']),edge_count=len(graph['edges']),unresolved_call_count=len(graph['unresolved_calls']),
                   export_path=str(export),findings_path=str(folder/'findings.json'),duration_seconds=duration)
    # Compact paths and full auth/registration functions are model-visible, raw graph remains auditable.
    records=[('C1','IPC 调用链与分析边界',json.dumps(summary,ensure_ascii=False,indent=2))]
    for index,function in enumerate(graph['functions'],2):
        records.append((f'C{index}',function['name'],f"FUNCTION {function['address']} {function['name']}\n[decompiler; verify against assembly]\n"+
                        function.get('pseudocode',function.get('decompile_error','unavailable'))+'\n[assembly]\n'+function['disassembly']+
                        '\n[CFG]\n'+json.dumps(function['cfg'],ensure_ascii=False)))
    for eid,title,output in records:
        path=folder/f'{eid}.txt';path.write_text(output)
        manifest['evidence'].append({'id':eid,'title':title,'output':output,'source':'tool','exit_code':0,'truncated':False,'argv':[], 'record_path':str(path)})
    if platform.system() == 'Darwin' and platform.machine() == 'arm64' and shutil.which('clang'):
        helper=folder/'sandbox-semantics'
        code,_=execute([shutil.which('clang'),'-arch','arm64',str(Path(__file__).parent/'tools/sandbox_semantics.c'),
                        '-framework','CoreFoundation','-framework','Security','-o',str(helper)],folder,
                       folder/'probe-build.stdout',folder/'probe-build.stderr',check,30)
        samples=[]
        if code==0:
            for mode in ('plain','sandboxed'):
                out,err=folder/f'{mode}.stdout',folder/f'{mode}.stderr'
                status,_=execute([str(helper),mode],folder,out,err,check,10)
                samples.append({'mode':mode,'exit_code':status,'stdout':out.read_text(),'stderr':err.read_text()})
        summary['api_calibration']={'build_exit_code':code,'samples':samples,'scope':'本机自建测试进程，只校准 sandbox API 返回值；没有联系目标或验证目标请求处理。'}
        manifest['evidence'].append({'id':'C99','title':'sandbox API 返回值独立动态校准','source':'tool','exit_code':code,
                                    'truncated':False,'argv':[], 'output':'本机自建测试进程；不是目标调用实验。\n'+
                                     '\n'.join(s['mode']+'\n'+s['stdout']+s['stderr'] for s in samples)})
    expected='/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/ATS.framework/Versions/A/Support/FontValidator'
    if manifest['metadata'].get('resolved_binary') == expected and summary.get('api_calibration',{}).get('build_exit_code') == 0:
        samples=[]
        for mode in ('plain','sandboxed'):
            out,err=folder/f'{mode}-request.stdout',folder/f'{mode}-request.stderr'
            status,_=execute([str(helper),mode,'--request-fontvalidator'],folder,out,err,check,10)
            samples.append({'mode':mode,'exit_code':status,'stdout':out.read_text(),'stderr':err.read_text()})
        out,err=folder/'denial-log.json',folder/'denial-log.stderr'
        code,_=execute(['/usr/bin/log','show','--last','1m','--style','json','--predicate',
                        'process == "FontValidator" AND eventMessage CONTAINS "Unable to get sandbox entitlement"'],
                       folder,out,err,check,20)
        probe={'samples':samples,'log_exit_code':code,'log_path':str(out),
               'log_excerpt':out.read_text(errors='replace')[:20000],
               'scope':'两次无字体载荷、非 plist 请求；只测试当前会话的端口可达性和拒绝线索。空回复不能区分通过鉴权后的解析失败与鉴权拒绝。日志无客户端 PID，时间相关不能证明唯一因果。私有 entitlement=true 客户端未动态测试。'}
        summary['ipc_probe']=probe
        manifest['evidence'].append({'id':'C98','title':'FontValidator 最小 IPC 请求对照','source':'tool','exit_code':code,'truncated':False,'argv':[],
                                    'output':probe['scope']+'\n'+ '\n'.join(s['mode']+'\n'+s['stdout']+s['stderr'] for s in samples)+'\n[server log]\n'+probe['log_excerpt']})
    manifest['call_graph']=summary
    return summary


if __name__ == '__main__':
    import argparse
    import hybrid_agent
    parser=argparse.ArgumentParser(description='ARM IPC call graph with evidence-backed paths')
    parser.add_argument('--manifest',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    folder=Path(args.output).resolve()
    manifest=json.loads(Path(args.manifest).read_text())
    result=collect(manifest,folder,lambda:None,lambda *a:print(*a,flush=True),hybrid_agent.execute)
    (folder/'evidence.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
    print(json.dumps({'status':result['status'],'findings':len(result.get('findings',[])),'output':str(folder)},ensure_ascii=False))
