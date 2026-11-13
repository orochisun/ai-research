"""Bounded real verification actions; unsupported probes are explicit blockers."""
import json
import platform
import plistlib
from pathlib import Path
import runtime_probe
import sandbox_profiles

KEYCHAIN='/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/XPCKeychainSandboxCheck.xpc/Contents/MacOS/XPCKeychainSandboxCheck'

def collect(manifest, folder, check, progress, execute):
    folder.mkdir(parents=True,exist_ok=True)
    sandbox_profiles.collect(manifest,folder/'profiles',check)
    result={'status':'blocked','scope':'真实验证；没有模拟返回值','attempts':[], 'blockers':[]}
    def command(argv,stem,timeout,stdin_path=None):
        check();out,err=folder/(stem+'.stdout'),folder/(stem+'.stderr')
        try:
            code,duration=execute(argv,folder,out,err,check,timeout,stdin_path) if stdin_path else execute(argv,folder,out,err,check,timeout)
            item={'argv':argv,'exit_code':code,'duration_seconds':duration}
        except (OSError,TimeoutError) as exc:item={'argv':argv,'error':str(exc),'exit_code':None}
        item.update(stdout=out.read_text(errors='replace') if out.exists() else '',stderr=err.read_text(errors='replace')[:10000] if err.exists() else '')
        result['attempts'].append(item);return item
    target=manifest['metadata'].get('resolved_binary')
    progress('运行环境调查','实验 Agent：执行已支持的只读探测，记录真实失败及证据缺口')
    if target==KEYCHAIN and platform.system()=='Darwin':
        # Reconfirm original identity and ARM availability before activating the system service.
        import hashlib
        from binary_policy import select_arm
        raw=Path(target).read_bytes();select_arm(raw)
        if hashlib.sha256(raw).hexdigest()!=manifest['metadata']['original_sha256']:raise ValueError('实验目标已变化')
        result['request']={'service':'com.apple.security.XPCKeychainSandboxCheck','op':'GrantKeychainPaths','transport':'xpc_connection_create','scope':'当前会话普通进程，未测试其他身份类别'}
        helper=folder/'keychain-probe'
        build=command(['/usr/bin/clang','-arch','arm64','-fblocks',str(Path(__file__).parent/'tools/keychain_paths_probe.m'),'-framework','Foundation','-o',str(helper)],'build',30)
        if build['exit_code']==0:
            probe=command([str(helper)],'request',12)
            try:
                reply=json.loads(probe['stdout']);result['reply']=reply
                result['status']='observed' if reply.get('status')=='reply' else 'blocked'
            except ValueError:result['blockers'].append('探测未返回有效 JSON，查看原始输出')
            if result.get('reply',{}).get('status')=='reply':
                # A separate, minimally entitled App Sandbox client checks the received capabilities.
                info=folder/'access-info.plist';entitlements=folder/'access.entitlements'
                info.write_bytes(plistlib.dumps({'CFBundleIdentifier':'local.ssj.boundary-check','CFBundleName':'SSJ Boundary Check','CFBundleVersion':'1'}))
                entitlements.write_bytes(plistlib.dumps({'com.apple.security.app-sandbox':True}))
                access=folder/'access-probe'
                compiled=command(['/usr/bin/clang','-arch','arm64','-fobjc-arc','-framework','Foundation',
                    '-Wl,-sectcreate,__TEXT,__info_plist,'+str(info),str(Path(__file__).parent/'tools/keychain_access_probe.m'),'-o',str(access)],'access-build',30)
                if compiled['exit_code']==0:
                    signed=command(['/usr/bin/codesign','--force','--sign','-','--identifier','local.ssj.boundary-check','--entitlements',str(entitlements),str(access)],'access-sign',15)
                    if signed['exit_code']==0:
                        measurement=command([str(access)],'access-result',15,folder/'request.stdout')
                        try:
                            result['access_comparison']=json.loads(measurement['stdout'])
                            result['access_comparison']['exit_code']=measurement['exit_code']
                            result['access_comparison']['entitlements']={'com.apple.security.app-sandbox':True}
                        except ValueError:result['blockers'].append('Sandbox 客户端没有有效 JSON；查看 access-result 的退出码和 stderr')
                    else:result['blockers'].append('Sandbox 客户端签名失败，查看 access-sign')
                else:result['blockers'].append('Sandbox 客户端编译失败，查看 access-build')
            try:
                mac=runtime_probe.MacProbe()
                result['runtime_samples']=[mac.sample(pid,Path(target)) for pid in mac.pids(Path(target))[:4]]
            except (OSError,ValueError) as exc: result['blockers'].append(str(exc))
        if result['status']!='observed':result['blockers'].append('当前调用进程未取得服务回复；不能将连接错误当成 entitlement 拒绝。未注册或修改系统服务。')
    else:
        result['blockers'].append('该目标尚无已实现的真实请求探测器；不把通用模拟对照作为验证。静态分析仍须完成可查证的计划项。')
    check()
    eid='V'+str(1+sum(e['id'].startswith('V') for e in manifest['evidence']))
    record=folder/'verification.json';record.write_text(json.dumps(result,ensure_ascii=False,indent=2))
    manifest['evidence'].append({'id':eid,'title':'真实实验尝试与阻塞原因','output':record.read_text(),'source':'tool','exit_code':None,'argv':[],'truncated':False,'record_path':str(record)})
    result['evidence_id']=eid
    return result
