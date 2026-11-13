"""Publish command-output receipts while the real model is still running."""
import json
from pathlib import Path


class LiveEvidenceRecorder:
    def __init__(self, events_path, prefix, workspace):
        self.events_path=Path(events_path)
        self.prefix=prefix
        self.workspace=Path(workspace)
        self.offset=0
        self.pending=b''
        self.records=[]
        self.seen=set()
        self.publish()

    def publish(self):
        index=[{'id':e['id'],'command':e['argv'][0][:240],
                'exit_code':e['exit_code'],'line_count':e['line_count'],
                'line_source_path':e['record_path']} for e in self.records]
        dest=self.workspace/'live-evidence-index.json'
        tmp=dest.with_suffix('.tmp')
        tmp.write_text(json.dumps(index,ensure_ascii=False,indent=2))
        tmp.replace(dest)

    def poll(self):
        if not self.events_path.exists(): return
        with self.events_path.open('rb') as stream:
            stream.seek(self.offset)
            chunk=stream.read()
            self.offset=stream.tell()
        data=self.pending+chunk
        lines=data.split(b'\n')
        self.pending=lines.pop()
        # Complete JSON at EOF is valid too (some CLI/test writers omit newline).
        if self.pending:
            try: json.loads(self.pending)
            except (ValueError,UnicodeDecodeError): pass
            else: lines.append(self.pending);self.pending=b''
        changed=False
        for line in lines:
            try: event=json.loads(line)
            except (ValueError,UnicodeDecodeError): continue
            item=event.get('item',{})
            if event.get('type')!='item.completed' or item.get('type')!='command_execution':continue
            event_id=item.get('id')
            if event_id and event_id in self.seen:continue
            if event_id:self.seen.add(event_id)
            eid=self.prefix+str(len(self.records)+1)
            output=item.get('aggregated_output','')
            path=self.workspace/(eid+'.txt');path.write_text(output)
            count=len(output.splitlines())
            record=dict(id=eid,title='模型实际执行：'+item.get('command',''),output=output,
                        argv=[item.get('command','')],exit_code=item.get('exit_code'),source='tool',
                        truncated=False,record_path=str(path),line_count=count,
                        transcript_path=str(self.events_path),
                        upstream_truncated=('tokens truncated' in output or 'Warning: truncated output' in output))
            record['truncated']=record['upstream_truncated']
            if len(output)>8192:
                record.update(content_storage='file',line_source_path=str(path),
                              output=f'命令返回内容保存在 {path}\n共 {count} 行；使用原文件行号引用。')
            self.records.append(record);changed=True
        if changed:self.publish()
