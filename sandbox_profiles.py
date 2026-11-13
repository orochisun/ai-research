"""Snapshot local application sandbox sources, including literal imports."""
import hashlib
import re
from pathlib import Path

ROOT=Path('/System/Library/Sandbox/Profiles')

def collect(manifest, folder, check, root=ROOT):
    if any(e['id']=='P1' for e in manifest['evidence']):return
    folder.mkdir(parents=True,exist_ok=True)
    queue=['application.sb'];seen=set()
    while queue and len(seen)<32:
        name=queue.pop(0)
        if name in seen:continue
        seen.add(name);check();path=(root/name).resolve()
        if not path.is_relative_to(root.resolve()):continue
        eid='P'+str(len(seen))
        try:
            raw=path.read_bytes()
            if len(raw)>512000:raise ValueError('profile 超过 512 KB')
            text=raw.decode();content='PATH: '+str(path)+'\nSHA256: '+hashlib.sha256(raw).hexdigest()+'\n'+text
            # Comments do not introduce imports.
            queue.extend(re.findall(r'\(import\s+"([^"\n]+)"\)',re.sub(r';[^\n]*','',text)))
            status=0
        except (OSError,ValueError) as exc:content='PATH: '+str(path)+'\nREAD ERROR: '+str(exc);status=1
        record=folder/(eid+'.txt');record.write_text(content)
        manifest['evidence'].append(dict(id=eid,title='Sandbox profile '+name,output=content,source='tool',exit_code=status,argv=['read',str(path)],truncated=False,record_path=str(record)))
