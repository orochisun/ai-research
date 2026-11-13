"""Run with an IDAPython-enabled Python, on its main thread, against a private ARM snapshot."""
import json
from pathlib import Path
import sys
import idapro
import ida_auto
import ida_bytes
import ida_funcs
import ida_gdl
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_lines
import ida_name
import ida_regfinder
import ida_segment
import ida_ua
import ida_xref
import idautils


def display(ea):
    name=ida_name.get_name(ea) or f'sub_{ea:x}'
    return ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM) or name


def line(ea):
    return ida_lines.tag_remove(ida_lines.generate_disasm_line(ea,0) or '')


def register(ea, name):
    reg=ida_idp.str2reg(name)
    if reg < 0: return None
    try:
        value=ida_regfinder.find_reg_value(ea,reg)
        return int(value) if value is not None else None
    except (TypeError,ValueError,RuntimeError): return None


def callback_value(ea, register_name, function):
    value=register(ea,register_name)
    if value is not None and ida_funcs.get_func(value):return value
    # Recover a callback loaded with ADR/ADRL, optionally PAC-signed and MOV'ed.
    # Restrict the scan to the current basic block; do not merge unrelated paths.
    block=next((b for b in ida_gdl.FlowChart(function) if b.start_ea<=ea<b.end_ea),None)
    if block is None:return None
    tracked=ida_idp.str2reg(register_name)
    for address in reversed(list(idautils.Heads(block.start_ea,ea))[-32:]):
        insn=ida_ua.insn_t()
        if not ida_ua.decode_insn(insn,address):continue
        mnemonic=insn.get_canon_mnem().upper()
        if ida_idp.is_call_insn(insn):return None
        if insn.ops[0].type!=ida_ua.o_reg or insn.ops[0].reg!=tracked:continue
        if mnemonic.startswith(('PAC','AUT')):continue
        if mnemonic=='MOV' and insn.ops[1].type==ida_ua.o_reg:
            tracked=insn.ops[1].reg;continue
        refs=[x for x in idautils.DataRefsFrom(address) if ida_funcs.get_func(x) and ida_funcs.get_func(x).start_ea==x]
        if mnemonic.startswith('ADR') and len(refs)==1:return refs[0]
        return None
    return None


def export(binary, output):
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from binary_policy import select_arm
    with binary.open("rb") as stream: raw=stream.read(64*1024*1024+1)
    if len(raw)>64*1024*1024: raise ValueError("Binary exceeds size limit")
    selected,_=select_arm(raw)
    if selected!=raw: raise ValueError("IDA accepts an extracted thin ARM slice only")
    if idapro.open_database(str(binary),True) != 0: raise RuntimeError('IDA open_database failed')
    try:
        ida_auto.auto_wait()
        decompiler=ida_hexrays.init_hexrays_plugin()
        nodes,edges,unresolved,registrations={},[],[],[]
        callbacks={'__CFMessagePortCreateLocalEx':'X4','_CFMessagePortCreateLocal':'X2','_xpc_main':'X0'}
        for start in idautils.Functions():
            f=ida_funcs.get_func(start);seg=ida_segment.getseg(start)
            segment=ida_segment.get_segm_name(seg) if seg else ''
            nodes[hex(start)]={'address':hex(start),'name':ida_name.get_name(start),'display':display(start),
                               'external':segment in ('__stubs','__auth_stubs','__objc_stubs','extern'), 'segment':segment,
                               'disassembly':[]}
            for ea in idautils.FuncItems(start):
                insn=ida_ua.insn_t()
                if not ida_ua.decode_insn(insn,ea):continue
                assembly=line(ea)
                nodes[hex(start)]['disassembly'].append(f'{ea:#x} {assembly}')
                mnemonic=insn.get_canon_mnem().upper()
                # Only actual call instructions or unconditional inter-function tail branches.
                # Never turn CFG branches / fallthrough xrefs into self-call edges.
                is_call=ida_idp.is_call_insn(insn)
                if not is_call and mnemonic != 'B':continue
                targets=[]
                for x in idautils.XrefsFrom(ea,0):
                    if x.type in (ida_xref.fl_CN,ida_xref.fl_CF) or (mnemonic=='B' and x.type in (ida_xref.fl_JN,ida_xref.fl_JF)):
                        target=ida_funcs.get_func(x.to)
                        if target and (is_call or target.start_ea!=start):targets.append((target.start_ea,'direct_call' if is_call else 'tail_call'))
                if is_call and not targets:
                    if insn.ops[0].type==ida_ua.o_reg:
                        regname=ida_idp.get_reg_name(insn.ops[0].reg,8)
                        value=register(ea,regname)
                        target=ida_funcs.get_func(value) if value is not None else None
                        if target and target.start_ea==value:targets.append((value,'resolved_register_call'))
                    if not targets:unresolved.append({'function':hex(start),'callsite':hex(ea),'instruction':assembly,'reason':'indirect target unresolved'})
                for target,kind in set(targets):
                    targetname=ida_name.get_name(target)
                    edges.append({'from':hex(start),'to':hex(target),'callsite':hex(ea),'kind':kind,'instruction':assembly})
                    if targetname in callbacks:
                        value=callback_value(ea,callbacks[targetname],f);func=ida_funcs.get_func(value) if value is not None else None
                        if func and func.start_ea==value:
                            registrations.append({'address':hex(value),'registration_function':hex(start),'callsite':hex(ea),
                                                  'api':targetname,'argument_register':callbacks[targetname],
                                                  'source_reason':f'IPC callback registered by {targetname} ({callbacks[targetname]})'})
        # Decompile IPC roots and auth-bearing functions, with full CFG and assembly.
        wanted={r['address'] for r in registrations}
        wanted.update(e['from'] for e in edges if any(k in nodes.get(e['to'],{}).get('name','') for k in ('SecTaskCopyValueForEntitlement','sandbox_check_by_audit_token')))
        wanted.update(r['registration_function'] for r in registrations)
        # Small services: include every internal function, including block invokes and
        # path helpers which are not ordinary call edges from the registration root.
        internal=[a for a,n in nodes.items() if not n['external']]
        if len(internal)<=48: wanted.update(internal)
        else:
            wanted.update(e['from'] for e in edges if any(k in nodes.get(e['to'],{}).get('name','') for k in ('xpc_', 'SecKeychain', 'sandbox_extension', 'getpw', 'getenv')))
        details=[]
        for address in sorted(wanted)[:48]:
            ea=int(address,16);f=ida_funcs.get_func(ea);node=nodes[address]
            detail={'address':address,'name':node['display'],'disassembly':'\n'.join(node['disassembly']),
                    'cfg':[{'start':hex(b.start_ea),'end':hex(b.end_ea),'successors':[hex(s.start_ea) for s in b.succs()]} for b in ida_gdl.FlowChart(f)]}
            if decompiler:
                try: detail['pseudocode']='\n'.join(ida_lines.tag_remove(x.line) for x in ida_hexrays.decompile(ea).get_pseudocode())
                except Exception as exc: detail['decompile_error']=str(exc)
            details.append(detail)
        output.write_text(json.dumps({'engine':'IDA/Hex-Rays','nodes':nodes,'edges':edges,'unresolved_calls':unresolved,
                                      'sources':registrations,'functions':details,'detail_coverage':{'selected':len(details),'candidates':len(wanted),'internal_functions':len(internal),'truncated':len(wanted)>48},
                                      'limitations':['Single ARM image only; imported library bodies are boundaries.',
                                                      'ObjC selector stubs do not resolve receiver implementations.',
                                                      'Static call edges do not prove path feasibility or attacker-controlled data flow.']},ensure_ascii=False,indent=2))
    finally: idapro.close_database()

if __name__=='__main__':export(Path(sys.argv[1]),Path(sys.argv[2]))
