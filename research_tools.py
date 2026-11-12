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

def inventory():
    names=['file','nm','otool','objdump','strings','clang','cargo']
    tools={n:shutil.which(n) for n in names}
    tools['dagger']=os.environ.get('NEXUS_DAGGER_BIN') or shutil.which('dagger')
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
    tools=inventory(); results=[]
    commands=[('file',[]),('nm',['-g']),('strings',['-a'])]
    if tools['otool']:commands += [('otool',['-hv']),('otool',['-L']),('otool',['-tvV'])]
    elif tools['objdump']:commands += [('objdump',['-f']),('objdump',['-d'])]
    for name,args in commands:
        if tools.get(name): results.append(execute([tools[name],*args,str(p)]))
    return {'engine':'native_binary_tools','path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'commands':results}

def dagger_audit(path):
    executable=inventory()['dagger']
    if not executable:return {'engine':'dagger','status':'unavailable','message':'配置 NEXUS_DAGGER_BIN 为内部 Dagger 引擎的绝对路径；不是同名 CI 工具'}
    return {'engine':'dagger','status':'executed','result':execute([executable,'audit',str(Path(path).resolve())],120)}

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
