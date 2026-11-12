import tempfile
from pathlib import Path
import unittest
from call_graph import find_paths


def node(name,external=False):
    return {'name':name,'display':name,'external':external,'disassembly':[name+' fixture assembly']}

def graph():
    return {'nodes':{'a':node('handler'),'b':node('wrapper'),'c':node('_open',True),'d':node('fake_selector')},
            'edges':[{'from':'a','to':'b','kind':'direct_call','callsite':'0x10','instruction':'bl wrapper'},
                     {'from':'b','to':'c','kind':'tail_call','callsite':'0x20','instruction':'b open'}],
            'sources':[{'address':'a','source_reason':'callback registration'}], 'unresolved_calls':[]}

class GraphTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def test_chain_has_per_hop_evidence_and_compatible_export(self):
        r=find_paths(graph(),'target',self.root);f=r['findings'][0]
        self.assertEqual(f['chain'],'handler -> wrapper -> _open')
        self.assertEqual(f['hops'],2)
        self.assertTrue(f['raw'].endswith('|UNVERIFIED'))
        self.assertIn('0x20',Path(f['disasm_file']).read_text())
    def test_unknown_objc_or_cfg_edges_do_not_create_paths(self):
        g=graph();g['edges'][0]['kind']='objc_selector_candidate'
        self.assertEqual(find_paths(g,'target',self.root)['findings'],[])
        g['edges'][0]['kind']='conditional_cfg_branch'
        self.assertEqual(find_paths(g,'target',self.root)['findings'],[])
    def test_cycles_terminate_and_external_bodies_are_not_followed(self):
        g=graph();g['nodes']['d']=node('_writev',True)
        g['edges'] += [{'from':'b','to':'a','kind':'direct_call'}, {'from':'c','to':'d','kind':'direct_call'}]
        r=find_paths(g,'target',self.root)
        self.assertEqual([f['sink'] for f in r['findings']],['_open'])
    def test_depth_limit_is_visible(self):
        r=find_paths(graph(),'target',self.root,max_depth=1)
        self.assertTrue(r['truncated']);self.assertEqual(r['findings'],[])
    def test_no_callback_source_is_not_guessed_from_names(self):
        g=graph();g['sources']=[]
        self.assertEqual(find_paths(g,'target',self.root)['findings'],[])
