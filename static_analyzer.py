"""User-configured, cancellable ARM-only static analyzer; no shell interpolation."""
import hashlib
import json
import os
from pathlib import Path
import re
from binary_policy import select_arm

DEFAULT = {'enabled': False, 'name': '静态分析工具', 'executable': '',
           'args': ['{arm_binary}'], 'format': 'json', 'output': 'stdout', 'timeout_seconds': 180}
LIMIT = 4 * 1024 * 1024


def validate(value):
    if not isinstance(value, dict): raise ValueError('配置必须是对象')
    c = {**DEFAULT, **value}
    c = {k: c[k] for k in DEFAULT}
    if type(c['enabled']) is not bool: raise ValueError('enabled 必须是布尔值')
    for key in ('name', 'executable', 'format', 'output'):
        if not isinstance(c[key], str) or len(c[key]) > 4096 or '\0' in c[key]: raise ValueError(f'{key} 无效')
    if not c['name'].strip(): raise ValueError('请填写工具名称')
    if c['format'] not in ('json', 'ndjson', 'text'): raise ValueError('输出格式必须为 json、ndjson 或 text')
    if type(c['timeout_seconds']) is not int or not 1 <= c['timeout_seconds'] <= 1800: raise ValueError('超时必须为 1–1800 秒')
    if not isinstance(c['args'], list) or len(c['args']) > 128 or any(not isinstance(a,str) or len(a)>4096 or '\0' in a for a in c['args']):
        raise ValueError('命令参数必须是字符串数组，最多 128 项')
    for arg in c['args']:
        if any(x not in ('arm_binary','output_dir','output_file') for x in re.findall(r'\{([^{}]+)\}',arg)):
            raise ValueError('只支持 {arm_binary}、{output_dir}、{output_file} 占位符')
    if c['output'] != 'stdout':
        p = Path(c['output'])
        if not c['output'] or p.is_absolute() or '..' in p.parts or c['output'] in ('.','target.arm','stdout.log','stderr.log','result.json'):
            raise ValueError('报告路径必须是输出目录内的相对文件名，且不能覆盖执行记录')
    if c['enabled']:
        p = Path(c['executable']).expanduser()
        if not p.is_absolute() or not p.is_file() or not os.access(p, os.X_OK): raise ValueError('软件路径必须是可执行文件的绝对路径')
        c['executable'] = str(p.resolve())
        if not any('{arm_binary}' in a for a in c['args']): raise ValueError('参数必须包含 {arm_binary}')
    return c


def collect(manifest, folder, check, progress, execute, config=None):
    folder.mkdir(parents=True, exist_ok=True)
    result = {'status':'disabled', 'engine':(config or DEFAULT)['name'],
              'meaning':'执行完成不代表覆盖完整或目标安全；工具报告中的发现尚未动态验证。'}
    argv = []
    try:
        c = validate(config or DEFAULT)
        result['config'] = c
        if c['enabled']:
            check()
            source = Path(next(e['argv'][-1] for e in manifest['evidence'] if e['id']=='T1'))
            raw = source.read_bytes(); arm, selection = select_arm(raw)
            if arm != raw or hashlib.sha256(raw).hexdigest() != manifest['metadata']['sha256']: raise ValueError('输入不是匹配的 ARM 切片快照')
            target = folder/'target.arm'; target.write_bytes(raw); target.chmod(0o400)
            out, err = folder/'stdout.log', folder/'stderr.log'
            report = out if c['output']=='stdout' else folder/c['output']
            report.parent.mkdir(parents=True,exist_ok=True)
            substitutions = {'arm_binary':str(target.resolve()), 'output_dir':str(folder.resolve()), 'output_file':str(report.resolve())}
            argv = [c['executable'], *[re.sub(r'\{(arm_binary|output_dir|output_file)\}',lambda m:substitutions[m[1]],a) for a in c['args']]]
            result.update(argv=argv,input_sha256=manifest['metadata']['sha256'],architecture=selection['architecture'],
                          stdout_path=str(out),stderr_path=str(err),report_path=str(report),coverage='unknown')
            progress('运行环境调查',f"{c['name']} · 自动静态分析 · ARM-only")
            code, duration = execute(argv, folder, out, err, check, c['timeout_seconds'])
            result.update(exit_code=code,duration_seconds=duration,status='executed' if code==0 else 'failed')
            result['diagnostic'] = err.read_bytes()[:12000].decode(errors='replace')
            if not report.resolve().is_relative_to(folder.resolve()): raise ValueError('工具报告指向输出目录之外')
            if not report.is_file(): raise ValueError('工具未生成指定报告')
            with report.open('rb') as f: data = f.read(LIMIT+1)
            if len(data)>LIMIT: raise ValueError('报告超过 4 MiB；原始文件已保留')
            text = data.decode('utf-8')
            payload = json.loads(text) if c['format']=='json' else [json.loads(line) for line in text.splitlines() if line.strip()] if c['format']=='ndjson' else text
            # Preserve arbitrary vendor schemas, never infer coverage from exit code or finding count.
            result['report'] = payload
    except TimeoutError as exc:
        result.update(status='timeout',error=str(exc),argv=argv)
    except (ValueError, OSError) as exc:
        result.update(status='failed' if result.get('exit_code') else 'invalid_output',error=str(exc),argv=argv)
    check()
    record = folder/'result.json'
    record.write_text(json.dumps(result,ensure_ascii=False,indent=2))
    evidence = json.dumps(result,ensure_ascii=False,indent=2)
    manifest['static_analysis'] = result
    manifest['evidence'].append({'id':'S1','title':'可配置静态分析工具 · 执行与报告','output':evidence[:100000],
                                'source':'tool','exit_code':result.get('exit_code'),'truncated':len(evidence)>100000,
                                'argv':argv,'record_path':str(record)})
    return result
