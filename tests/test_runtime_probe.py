import ctypes as C
import hashlib
import json
import plistlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import runtime_probe as rp


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = self.root/'target'
        self.target.write_bytes(b'fixture')

    def tearDown(self): self.tmp.cleanup()

    def manifest(self):
        return {'metadata': {'original_sha256': hashlib.sha256(self.target.read_bytes()).hexdigest()},
                'evidence': [{'id': 'T0', 'output': '{}'}, {'id': 'T2', 'output': ' U _CFMessagePortCreateLocal'}]}

    def test_launch_matching_is_exact_executable_not_name(self):
        for name, program in [('right',str(self.target)),('wrong',str(self.root/'other'/'target'))]:
            (self.root/f'{name}.plist').write_bytes(plistlib.dumps({'Label':name,'ProgramArguments':[program]}))
        (self.root/'broken.plist').write_bytes(b'<?xml nope')
        entries, errors = rp.launch_definitions(self.target,[str(self.root)])
        self.assertEqual([x['label'] for x in entries], ['right'])
        self.assertEqual(len(errors), 1)

    def test_no_activation_when_live_program_differs(self):
        definition = {'label':'test','domain':'gui/501','mach_services':{},'sockets':{}}
        probe = Mock(); probe.pids.return_value = []
        calls = []
        def execute(argv, cwd, out, err, *args):
            calls.append(argv); out.write_text('program = /different/target\n'); err.write_text(''); return 0,.1
        with patch('runtime_probe.sys.platform','darwin'), patch('runtime_probe.launch_definitions',return_value=([definition],[])), patch('runtime_probe.MacProbe',return_value=probe):
            r=rp.investigate(self.target,self.manifest(),self.root/'runtime',lambda:None,lambda *a:None,execute)
        self.assertFalse(any('kickstart' in a for a in calls))
        self.assertEqual(r['status'],'incomplete')
        self.assertEqual(r['processes'],[])
        raw = Path(r['attempts'][0]['stdout_path']).read_text()
        evidence = (self.root/'runtime'/'R2.txt').read_text()
        self.assertIn(raw, evidence)

    def test_changed_binary_aborts_before_activation(self):
        manifest=self.manifest();self.target.write_bytes(b'changed')
        with patch('runtime_probe.sys.platform','darwin'), patch('runtime_probe.MacProbe') as probe:
            with self.assertRaisesRegex(ValueError,'发生变化'):
                rp.investigate(self.target,manifest,self.root/'runtime',lambda:None,lambda *a:None,Mock())
            probe.assert_not_called()

    def make_probe(self, sandbox_result=-1):
        probe = rp.MacProbe.__new__(rp.MacProbe)
        probe.identity=Mock(return_value={'pid':12,'uid':501,'euid':501,'start_sec':1})
        probe.path=Mock(return_value=str(self.target))
        def arch(pid, kind, arg, buf, size):
            C.cast(buf,C.POINTER(C.c_int32))[0]=0x0100000c
            return size
        probe.proc=Mock();probe.proc.proc_pidinfo.side_effect=arch
        probe.system=Mock();probe.system.csops.return_value=-1
        probe.sandbox=Mock();probe.sandbox.sandbox_check.return_value=sandbox_result
        return probe

    def test_failed_sandbox_query_is_unknown_not_unsandboxed(self):
        sample=self.make_probe().sample(12,self.target)
        self.assertEqual(sample['sandbox']['status'],'unknown')
        self.assertIsNone(sample['sandbox']['sandboxed'])
        self.assertEqual(sample['entitlements']['status'],'unknown')

    def test_runtime_entitlements_are_decoded_from_process_blob(self):
        probe=self.make_probe(1)
        payload=plistlib.dumps({'com.example.permission':True})
        import struct
        blob=struct.pack('>II',0xfade7171,len(payload)+8)+payload
        def csops(pid,operation,buffer,size):
            self.assertEqual(operation,7)
            C.memmove(buffer,blob,len(blob));return 0
        probe.system.csops.side_effect=csops
        r=probe.sample(12,self.target)
        self.assertEqual(r['entitlements']['values'],{'com.example.permission':True})
        self.assertTrue(r['sandbox']['sandboxed'])

    def test_pid_reuse_discards_sample(self):
        probe=self.make_probe(1)
        probe.identity.side_effect=[{'pid':12,'start_sec':1},{'pid':12,'start_sec':2}]
        with self.assertRaisesRegex(ValueError,'身份'):probe.sample(12,self.target)

    def test_x86_process_rejected_before_entitlement_query(self):
        probe=self.make_probe()
        def arch(pid,kind,arg,buf,size):
            C.cast(buf,C.POINTER(C.c_int32))[0]=0x01000007
            return size
        probe.proc.proc_pidinfo.side_effect=arch
        with self.assertRaisesRegex(ValueError,'ARM'):probe.sample(12,self.target)
        probe.system.csops.assert_not_called()

    def test_non_macos_does_not_invent_device_runtime(self):
        with patch('runtime_probe.sys.platform','linux'),patch('runtime_probe.MacProbe') as probe:
            r=rp.investigate(self.target,self.manifest(),self.root/'runtime',lambda:None,lambda *a:None,Mock())
        self.assertEqual(r['status'],'incomplete');probe.assert_not_called()
        self.assertIn('iOS',' '.join(r['limitations']))
