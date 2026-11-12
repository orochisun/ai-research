"""Internal Dagger audit-stream integration; never auto-select the unrelated CI CLI."""
import hashlib
import json
import os
from pathlib import Path
from binary_policy import select_arm


def executable():
    configured=os.environ.get('NEXUS_DAGGER_BIN')
    if configured:return Path(configured).expanduser().resolve()
    root=Path(__file__).resolve().parent
    for candidate in (root/'engines/dagger/target/release/dagger',root.parent.parent/'dagger-main/target/release/dagger',root.parent.parent/'dagger/target/release/dagger'):
        if candidate.is_file():return candidate.resolve()
    return None


def parse_stream(path):
    report=None;done=False;warnings=[];errors=[];progress=None;deadline=False;events=0;protocol=None;run_id=None;findings=[];coverage=None
    with path.open() as stream:
        for line in stream:
            if not line.strip():continue
            event=json.loads(line);events+=1
            current=4 if event.get('protocolVersion')==4 else 1
            if protocol is not None and protocol!=current:raise ValueError('混合 Dagger 协议')
            protocol=current
            if current==4:
                if event.get('sequence')!=events-1 or (run_id is not None and run_id!=event.get('runId')):
                    raise ValueError('Dagger 流序号或运行 ID 不一致')
                run_id=event.get('runId')
                frame=event['event'];kind=frame['kind'];payload=frame.get('payload',{})
                if done:raise ValueError('Dagger 关闭后仍有事件')
                if events==1 and kind!='run.open':raise ValueError('Dagger 缺少 run.open')
                if kind=='finding.core':findings.append(payload['finding'])
                elif kind=='progress':progress=payload
                elif kind=='coverage':coverage=payload
                elif kind=='run.close':
                    done=payload.get('outcome')=='complete';coverage=payload.get('coverage')
                    if payload.get('findings')!=len(findings):raise ValueError('Dagger 发现数量不一致')
                    report={'protocol_version':4,'findings':findings,'coverage':coverage,'summary':payload}
                    deadline=not done or not isinstance(coverage,dict) or coverage.get('status')!='complete'
                continue
            if event.get('schema')!='dagger.audit.stream' or event.get('schema_version')!=1:
                raise ValueError('不支持的 Dagger audit stream schema')
            kind=event.get('type')
            if kind=='audit_summary':report=event.get('report')
            if kind=='audit_done':done=True
            if kind=='warning':warnings.append(event.get('message',''))
            if kind=='audit_error':errors.append(event.get('message',''))
            if kind=='scanning':
                progress=event
                deadline=deadline or bool(event.get('deadline_reached')) or bool(event.get('limit_reasons'))
    if report is not None and (not isinstance(report,dict) or not isinstance(report.get('findings'),list)):
        raise ValueError('Dagger 最终报告结构无效')
    if report and isinstance(report.get('coverage'),dict):
        deadline=deadline or report['coverage'].get('status') in ('partial','limited')
    return {'report':report,'done':done,'warnings':warnings,'errors':errors,'last_progress':progress,'limited':deadline,'event_count':events}


def collect(manifest, folder, check, progress, execute):
    folder.mkdir(parents=True,exist_ok=True)
    engine=executable()
    result={'engine':'dagger','status':'unavailable','findings':[], 'meaning':'静态引擎报告，不代表动态验证或确认漏洞。'}
    if not engine or not engine.is_file():
        result['error']='未找到内部 Dagger；设置 NEXUS_DAGGER_BIN 指向内部引擎。'
    else:
        source=Path(next(e['argv'][-1] for e in manifest['evidence'] if e['id']=='T1'))
        raw=source.read_bytes();selected,selection=select_arm(raw)
        if raw!=selected or hashlib.sha256(raw).hexdigest()!=manifest['metadata']['sha256']:
            raise ValueError('Dagger 输入必须是匹配的 ARM 切片快照')
        target=folder/'target.arm';target.write_bytes(raw);target.chmod(0o400)
        result.update(executable=str(engine),binary_sha256=hashlib.sha256(engine.read_bytes()).hexdigest(),
                      input_sha256=manifest['metadata']['sha256'],architecture=selection['architecture'])
        stdout,stderr=folder/'audit.ndjson',folder/'stderr.log'
        help_out,help_err=folder/'help.txt',folder/'help-stderr.log'
        argv=[str(engine),'audit',str(target),'--time-limit','90s']
        progress('运行环境调查','Dagger 静态审计 · ARM-only · 90 秒引擎预算')
        try:
            help_code,_=execute([str(engine),'audit','--help'],folder,help_out,help_err,check,10)
            if help_code:raise OSError('Dagger audit --help 失败；查看 help-stderr.log')
            capabilities=help_out.read_text() if help_out.exists() else ''
            options=['--workers','1'] if '--workers' in capabilities and '--detail' not in capabilities else ['--detail','full']
            argv.extend(options)
            code,duration=execute(argv,folder,stdout,stderr,check,110)
            result.update(exit_code=code,duration_seconds=duration,status='failed' if code else 'incomplete')
        except TimeoutError as exc:
            result.update(exit_code=None,status='timeout',error=str(exc))
        except OSError as exc:
            result.update(exit_code=None,status='failed',error=str(exc))
        result.update(argv=argv,stdout_path=str(stdout),stderr_path=str(stderr))
        if stderr.exists():
            with stderr.open('rb') as stream: result['diagnostic']=stream.read(12000).decode(errors='replace')
        if stdout.exists():
            try:
                parsed=parse_stream(stdout)
                report=parsed.pop('report');result.update(parsed)
                if report:
                    report_path=folder/'report.json';report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2))
                    result.update(report_path=str(report_path),summary=report.get('summary'),coverage=report.get('coverage'),
                                  tool=report.get('tool'),findings=report['findings'][:30],findings_truncated=len(report['findings'])>30)
                    if result['status'] not in ('timeout','failed'):
                        result['status']='completed' if parsed['done'] and not parsed['limited'] and not parsed['errors'] else 'incomplete'
            except (ValueError,TypeError,KeyError) as exc:
                result.update(status='invalid_output',error=str(exc))
    check()
    (folder/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
    manifest['dagger_analysis']=result
    manifest['evidence'].append({'id':'D1','title':'Dagger 静态审计结果与覆盖范围','output':json.dumps(result,ensure_ascii=False,indent=2),
                                'source':'tool','exit_code':result.get('exit_code'),'truncated':result.get('findings_truncated',False),
                                'argv':result.get('argv',[]),'record_path':str(folder/'result.json')})
    return result
