"""Auditable CLI adapters. Run inside a task workspace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from binary_policy import select_arm

def inventory():
    names=['file','nm','otool','objdump','strings','clang','cargo']
    tools={n:shutil.which(n) for n in names}
    from dagger_adapter import executable
    engine=executable()
    tools['dagger']=str(engine) if engine else None
    return tools

def execute(argv, timeout=30):
    started=time.monotonic()
    with tempfile.TemporaryFile() as output:
        try:
            p=subprocess.run(argv,stdout=output,stderr=subprocess.STDOUT,timeout=timeout)
            code=p.returncode
        except subprocess.TimeoutExpired:
            code=None
        output.seek(0,2);size=output.tell();output.seek(0)
        text=output.read(200000).decode(errors='replace')
    return {'argv':argv,'exit_code':code,'timed_out':code is None,'output':text,'truncated':size>200000,'duration_seconds':round(time.monotonic()-started,2)}

def analyze_binary(path):
    p=Path(path).resolve()
    if not p.is_file():raise ValueError('文件不存在')
    with p.open('rb') as stream: raw=stream.read(64*1024*1024+1)
    if len(raw)>64*1024*1024:raise ValueError('目标超过 64 MiB 限制')
    selected,selection=select_arm(raw)
    tools=inventory(); results=[]
    commands=[('file',[]),('nm',['-g']),('strings',['-a'])]
    if tools['otool']:commands += [('otool',['-hv']),('otool',['-L']),('otool',['-tvV'])]
    elif tools['objdump']:commands += [('objdump',['-f']),('objdump',['-d'])]
    with tempfile.TemporaryDirectory() as directory:
        snapshot=Path(directory)/'target.arm';snapshot.write_bytes(selected);snapshot.chmod(0o400)
        for name,args in commands:
            if tools.get(name): results.append(execute([tools[name],*args,str(snapshot)]))
    return {'engine':'native_binary_tools','path':str(p),'sha256':hashlib.sha256(raw).hexdigest(),
            'selected_sha256':hashlib.sha256(selected).hexdigest(),'selection':selection,'commands':results}

def dagger_audit(path):
    import dagger_adapter
    import hybrid_agent
    p=Path(path).resolve()
    with p.open('rb') as stream: raw=stream.read(64*1024*1024+1)
    if len(raw)>64*1024*1024:raise ValueError('目标超过 64 MiB 限制')
    selected,selection=select_arm(raw)
    with tempfile.TemporaryDirectory() as directory:
        folder=Path(directory);snapshot=folder/'target.arm';snapshot.write_bytes(selected)
        manifest={'metadata':{'sha256':hashlib.sha256(selected).hexdigest()},
                  'evidence':[{'id':'T1','argv':['file',str(snapshot)]}]}
        # Keep the report/log paths valid after returning from the CLI.
        output=Path.cwd()/'dagger-runs'/str(time.time_ns())
        return dagger_adapter.collect(manifest,output,lambda:None,lambda *a:None,hybrid_agent.execute)

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['inventory','binary','dagger']);p.add_argument('target',nargs='?');p.add_argument('--output',required=True);a=p.parse_args()
    workspace=Path.cwd().resolve();out=Path(a.output).resolve()
    if not out.is_relative_to(workspace):raise ValueError('输出必须位于工作区')
    if a.action!='inventory':
        target=Path(a.target).resolve()
        if not target.is_relative_to(workspace):raise ValueError('目标必须位于工作区')
    result=inventory() if a.action=='inventory' else analyze_binary(a.target) if a.action=='binary' else dagger_audit(a.target)
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,ensure_ascii=False,indent=2));print(json.dumps({'saved':str(out),'engine':result.get('engine'),'status':result.get('status','completed')},ensure_ascii=False))
if __name__=='__main__':main()
