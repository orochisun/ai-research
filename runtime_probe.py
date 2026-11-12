"""Default macOS runtime investigation. No debugger, privilege change or IPC payloads.

PID-bound queries use libproc and csops; sandbox presence uses sandbox_check(pid, NULL, 0).
Apple csops definitions: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h
The private sandbox API is version-dependent; failures remain unknown, never 'unsandboxed'.
"""
import ctypes as C
import hashlib
import platform
import json
import os
from pathlib import Path
import plistlib
import re
import struct
import sys
import time
from xml.parsers.expat import ExpatError


class BSDInfo(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in ('flags', 'status', 'xstatus', 'pid', 'ppid', 'euid', 'egid', 'uid', 'gid', 'svuid', 'svgid', 'reserved')] + [
        ('comm', C.c_char * 16), ('name', C.c_char * 32)] + [(n, C.c_uint32) for n in ('nfiles', 'pgid', 'pjobc', 'tdev', 'tpgid')] + [
        ('nice', C.c_int32), ('start_sec', C.c_uint64), ('start_usec', C.c_uint64)]


class MacProbe:
    def __init__(self):
        self.proc = C.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        self.system = C.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        self.sandbox = C.CDLL('/usr/lib/libsandbox.1.dylib', use_errno=True)
        self.proc.proc_pidpath.argtypes = [C.c_int, C.c_void_p, C.c_uint32]
        self.proc.proc_pidinfo.argtypes = [C.c_int, C.c_int, C.c_uint64, C.c_void_p, C.c_int]
        self.proc.proc_listallpids.argtypes = [C.c_void_p, C.c_int]
        self.system.csops.argtypes = [C.c_int, C.c_uint, C.c_void_p, C.c_size_t]
        self.sandbox.sandbox_check.argtypes = [C.c_int, C.c_char_p, C.c_int]

    def path(self, pid):
        buf = C.create_string_buffer(4096)
        return os.fsdecode(buf.value) if self.proc.proc_pidpath(pid, buf, len(buf)) > 0 else None

    def pids(self, target):
        count = self.proc.proc_listallpids(None, 0)
        if count <= 0: raise OSError(C.get_errno(), 'proc_listallpids failed')
        buf = (C.c_int * (count + 1024))()
        count = self.proc.proc_listallpids(buf, C.sizeof(buf))
        return [pid for pid in buf[:max(0, count)] if self.path(pid) == str(target)]

    def identity(self, pid):
        info = BSDInfo()
        if self.proc.proc_pidinfo(pid, 3, 0, C.byref(info), C.sizeof(info)) != C.sizeof(info):
            raise OSError(C.get_errno(), 'proc_pidinfo failed')
        return {k: getattr(info, k) for k in ('pid', 'ppid', 'uid', 'euid', 'gid', 'egid', 'svuid', 'start_sec', 'start_usec')}

    def sample(self, pid, target):
        start = self.identity(pid)
        if self.path(pid) != str(target): raise ValueError('PID executable mismatch')
        arch = (C.c_int32 * 2)()
        arch_rc = self.proc.proc_pidinfo(pid, 19, 0, arch, C.sizeof(arch))
        if arch_rc != C.sizeof(arch) or arch[0] not in (12, 0x0100000c):
            raise ValueError('运行进程不是可确认的 ARM 架构，拒绝进一步分析')
        blob = C.create_string_buffer(1024 * 1024)
        C.set_errno(0)
        rc = self.system.csops(pid, 7, blob, len(blob))
        ent = {'status': 'unknown', 'method': 'csops(CS_OPS_ENTITLEMENTS_BLOB)', 'return_code': rc, 'errno': C.get_errno()}
        if rc == 0:
            magic, size = struct.unpack('>II', blob.raw[:8])
            if magic == 0xfade7171 and 8 < size <= len(blob):
                try:
                    ent.update(status='confirmed', values=plistlib.loads(blob.raw[8:size].rstrip(b'\0')))
                except (ValueError, plistlib.InvalidFileException, ExpatError) as exc: ent['error'] = str(exc)
            else: ent['error'] = 'No valid XML entitlement blob; not proof of no entitlements'
        C.set_errno(0)
        sb = self.sandbox.sandbox_check(pid, None, 0)
        se = C.get_errno()
        sandbox = {'status': 'confirmed' if sb in (0, 1) and se == 0 else 'unknown',
                   'sandboxed': bool(sb) if sb in (0, 1) and se == 0 else None,
                   'method': 'sandbox_check(pid, NULL, 0)', 'return_code': sb, 'errno': se,
                   'scope': '采样时是否存在 sandbox；不代表已枚举有效策略或 sandbox extensions'}
        end = self.identity(pid)
        if start != end or self.path(pid) != str(target): raise ValueError('进程身份在采样中变化，丢弃结果')
        return {'observed_at': time.time(), 'identity': start, 'executable': str(target),
                'architecture': {'cpu_type': arch[0], 'cpu_subtype': arch[1]},
                'entitlements': ent, 'sandbox': sandbox}


def launch_definitions(target, roots=None):
    target = Path(target).resolve()
    roots = roots or ['/System/Library/LaunchAgents', '/System/Library/LaunchDaemons',
                      '/Library/LaunchAgents', '/Library/LaunchDaemons', str(Path.home()/'Library/LaunchAgents')]
    found, errors = [], []
    for root in roots:
        for path in sorted(Path(root).glob('*.plist')):
            try:
                if path.stat().st_size > 1024*1024: continue
                value = plistlib.loads(path.read_bytes())
                args = value.get('ProgramArguments', [])
                program = value.get('Program') or (args[0] if args else None)
                if not isinstance(program, str) or Path(program).resolve() != target: continue
                label = value.get('Label')
                if not isinstance(label, str) or not label or '/' in label: continue
                found.append({'path': str(path), 'label': label, 'program': str(target), 'arguments': args,
                              'domain': 'system' if Path(root).name == 'LaunchDaemons' else f'gui/{os.getuid()}',
                              'mach_services': value.get('MachServices', {}), 'sockets': value.get('Sockets', {}),
                              'configured_user': value.get('UserName'), 'configured_group': value.get('GroupName')})
            except (OSError, ValueError, TypeError, plistlib.InvalidFileException, ExpatError) as exc:
                errors.append({'path': str(path), 'error': str(exc)})
    return found, errors


def investigate(target, manifest, workspace, check, progress, execute):
    """Bounded adaptive collection: existing PID -> registered launch -> re-sample.
    No arbitrary binary launch; normal registered jobs are started without -k or config changes.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    evidence = manifest['evidence']
    result = {'policy': 'runtime-context-before-planning-v1', 'platform': sys.platform,
              'status': 'investigating', 'processes': [], 'launch_definitions': [], 'attempts': [],
              'ipc': {}, 'limitations': [], 'started_services': []}
    def record(title, payload, raw_output=None):
        eid = 'R' + str(1 + sum(e['id'].startswith('R') for e in evidence))
        text = raw_output if raw_output is not None else json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        (workspace/f'{eid}.txt').write_text(text)
        evidence.append({'id': eid, 'title': title, 'output': text, 'source': 'tool', 'exit_code': 0,
                         'truncated': False, 'argv': [], 'record_path': str(workspace/f'{eid}.txt')})
        return eid
    def command(name, argv):
        check(); progress('运行环境调查', name)
        number = len(result['attempts']) + 1
        out, err = workspace/f'command-{number}.stdout', workspace/f'command-{number}.stderr'
        try:
            code, duration = execute(argv, workspace, out, err, check, 12)
            item = {'argv': argv, 'exit_code': code, 'duration_seconds': duration,
                    'stdout': out.read_text(errors='replace')[:60000], 'stderr': err.read_text(errors='replace')[:10000]}
        except (OSError, TimeoutError) as exc: item = {'argv': argv, 'error': str(exc), 'exit_code': None}
        metadata = {k:v for k,v in item.items() if k not in ('stdout', 'stderr')}
        item['evidence_id'] = record(name, metadata, json.dumps(metadata, ensure_ascii=False, indent=2) + '\n[stdout]\n' + item.get('stdout','') + '\n[stderr]\n' + item.get('stderr',''))
        result['attempts'].append(dict(metadata, evidence_id=item['evidence_id'], stdout_path=str(out), stderr_path=str(err)))
        return item
    if sys.platform != 'darwin':
        result['limitations'].append('当前主机不是 macOS；iOS 运行时需要连接设备采集器，不能用主机身份代替。')
    else:
        target = Path(target).resolve()
        with target.open('rb') as stream:
            current = stream.read(64 * 1024 * 1024 + 1)
        if hashlib.sha256(current).hexdigest() != manifest['metadata']['original_sha256']:
            raise ValueError('目标在静态采集后发生变化，拒绝启动或关联运行时证据')
        definitions, errors = launch_definitions(target)
        result['launch_definitions'] = definitions
        record('匹配目标可执行路径的启动配置', {'matches': definitions, 'read_errors': errors})
        try:
            probe = MacProbe()
            pids = probe.pids(target)
            for definition in definitions[:4]:
                check()
                service = definition['domain'] + '/' + definition['label']
                before = command('查询注册服务 ' + service, ['/bin/launchctl', 'print', service])
                # Verify live configuration also points at this target before starting.
                live_program = re.search(r'^\s*program = (.+)$', before.get('stdout', ''), re.M)
                if platform.machine() == 'arm64' and not pids and before['exit_code'] == 0 and live_program and Path(live_program[1]).resolve() == target:
                    started = command('正常激活服务 ' + service, ['/bin/launchctl', 'kickstart', service])
                    if started['exit_code'] == 0:
                        result['started_services'].append(service)
                        for _ in range(15):
                            check(); pids = probe.pids(target)
                            if pids: break
                            time.sleep(.1)
                command('采样服务注册与端点 ' + service, ['/bin/launchctl', 'print', service])
            for pid in probe.pids(target)[:8]:
                check(); progress('运行环境调查', f'PID {pid} · UID / entitlements / sandbox')
                try:
                    sample = probe.sample(pid, target)
                    # Second sample after service initialization, preserving any state transition.
                    time.sleep(.3); check()
                    second = probe.sample(pid, target)
                    if sample['identity'] != second['identity']: raise ValueError('PID identity changed')
                    sample['followup'] = second
                    sample['evidence_id'] = record('PID 运行时身份、权限与 sandbox', sample)
                    result['processes'].append(sample)
                    command(f'PID {pid} 文件描述符与 socket', ['/usr/sbin/lsof', '-nP', '-a', '-p', str(pid)])
                except (OSError, ValueError) as exc:
                    record('运行时采样失败', {'pid': pid, 'error': str(exc)})
                    result['limitations'].append(f'PID {pid}: {exc}')
            if not result['processes']:
                result['limitations'].append('未取得稳定的 ARM 目标进程；已尝试进程匹配及已注册服务正常启动。UID、运行时权限与 sandbox 保持未知。')
        except (OSError, AttributeError) as exc: result['limitations'].append(str(exc))
    outputs = {e['id']: e['output'] for e in evidence}
    # Symbol references are leads, not established inbound endpoints.
    ipc_lines = [line for line in outputs.get('T2', '').splitlines() if re.search(r'xpc_|NSXPC|CFMessagePort|bootstrap_|mach_msg|audit_token|SecTask|socket|listen|accept', line)]
    disassembly = next((e for e in evidence if e['id'] == 'T7'), {})
    if disassembly.get('stdout_path'):
        try:
            with Path(disassembly['stdout_path']).open() as stream:
                lines = stream.read(8 * 1024 * 1024).splitlines()
            excerpts, label = [], ''
            for index, line in enumerate(lines):
                if line.endswith(':'): label = line
                if re.search(r'\bbl\s+.*(CFMessagePort|SecTask|sandbox_check|xpc_|bootstrap_|mach_msg)', line):
                    excerpts.append({'enclosing_label': label, 'lines': '\n'.join(lines[max(0,index-10):index+9])})
                if len(excerpts) >= 40: break
            record('ARM IPC 与调用方鉴权调用点', {}, 'SOURCE: T7 full stdout\n局部调用点；不证明完整鉴权或可达性\n' + '\n\n'.join(e['enclosing_label'] + '\n' + e['lines'] for e in excerpts))
        except OSError as exc: result['limitations'].append(str(exc))
    result['ipc'] = {'registered_services': [{'label': d['label'], 'mach_services': d['mach_services'], 'sockets': d['sockets']} for d in result['launch_definitions']],
                     'static_api_leads': ipc_lines[:100], 'api_evidence_id': 'T2',
                     'scope': '注册端点、进程 fd 和静态 API 线索；未向服务发送业务消息，调用方鉴权与完整可达性需进一步自动分析。'}
    # Only read system sandbox profiles explicitly named by target strings.
    profiles = sorted(set(re.findall(r'/usr/share/sandbox/[\w.-]+\.sb', outputs.get('T3', ''))))[:8]
    for profile in profiles:
        try:
            content = Path(profile).read_text()[:40000]
            record('目标引用的 sandbox profile（静态，非加载证明）', {'path': profile, 'content': content, 'loaded_at_runtime': 'unknown'})
        except OSError as exc: result['limitations'].append(f'{profile}: {exc}')
    result['status'] = 'observed' if result['processes'] else 'incomplete'
    result['limitations'].extend(['macOS 主机采样不能代表 iOS 设备；未连接设备时 iOS 动态项为未知。',
                                '启动由 launchd 管理的服务后不卸载或强杀该系统服务；运行状态由系统管理。'])
    result['evidence_id'] = record('默认基础调查结论', result)
    manifest['runtime_investigation'] = result
    manifest['metadata']['runtime_observed'] = bool(result['processes'])
    manifest['metadata']['service_activation_succeeded'] = bool(result['started_services'])
    manifest['metadata']['target_executed_by_workflow'] = bool(result['started_services'])
    manifest['metadata']['target_executed'] = bool(result['started_services'])
    manifest['metadata']['runtime_scope'] = '已存在进程或 launchd 正常启动；未发送漏洞实验输入'
    evidence[0]['output'] = json.dumps(manifest['metadata'], ensure_ascii=False, indent=2)
    return result
