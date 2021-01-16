from __future__ import print_function
from struct import *
import ida_ua
import ida_bytes
import idc
import idaapi
import idautils
import os
import sys
import pickle
import time
import json
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.analysis.binary import Container
from miasm.core.bin_stream import bin_stream, bin_stream_str, bin_stream_elf, bin_stream_pe
from miasm.arch.x86.arch import mn_x86
from miasm.expression.expression import *
from miasm.expression.simplifications import *
from miasm.expression.simplifications_cond import *
from miasm.core.cpu import *

machine = Machine('x86_64')
INIT_REG = machine.mn.regs.regs_init

def u32(data):
    return unpack("<I", data)[0]

def u64(data):
    return unpack("<Q", data)[0]

def p32(val):
    return pack("<I", val)

def p64(val):
    return pack("<Q", val)

def GetBBLFromEA(tgtEA):
    tgtEA = int(tgtEA)
    f = idaapi.get_func(tgtEA)
    if not f:
        return None

    fc = idaapi.FlowChart(f, None, 0x4)

    for block in fc:
        if block.startEA <= tgtEA:
            if block.endEA > tgtEA:
                return block
    return None

def ExecuteSymbolicSingleStep(addr, state=INIT_REG):
    size = idc.ItemSize(addr)
    code = idc.GetManyBytes(addr, size)
    loc_db = LocationDB()

    base = addr
    try:
        ins = mn_x86.dis(bin_stream_str(code, base_address=base), 64, base)
    except:
        return state.copy()

    ira = machine.ira(loc_db)
    ircfg = ira.new_ircfg()
    try:
        ira.add_instr_to_ircfg(ins, ircfg)
        sb = SymbolicExecutionEngine(ira, state)
        symbolic_pc = sb.run_at(ircfg, base)
    except:
        return state.copy()
    ret = state.copy()
    for key, value in sb.modified():
        if isinstance(value, ExprOp) and value.op == "call_func_ret":
            value = ExprInt(0, 64)
        ret[key] = value
    return ret

def RetrievePossibleIdentifiersOfRVA(rva, inst_type):
    assert(len(inst_type[rva]) == 1)
    return inst_type[rva].values()

def ExtractMemAccessBaseReg(exprs):
    for single_expr in exprs:
        if isinstance(single_expr, ExprMem):
            if isinstance(single_expr.ptr, ExprId):
                return single_expr.ptr.name.replace("_init", "")
            elif (isinstance(single_expr.ptr, ExprOp) and single_expr.ptr.op == "+" and
                    isinstance(single_expr.ptr.args[0], ExprId) and 
                    isinstance(single_expr.ptr.args[1], ExprInt)):
                return single_expr.ptr.args[0].name.replace("_init", "")
        elif isinstance(single_expr, ExprOp):
            for arg_expr in single_expr.args:
                ret = ExtractMemAccessBaseReg([arg_expr])
                if ret != None:
                    return ret
    return None

def main():
    path_before = idaapi.askstr(0, "", "Please give me path of type information file").strip()
    f_before = open(path_before, "rb")
    if not len(path_before) or not f_before:
        raise Exception("Error on opening the type information file")
    
    typed_inst_info = json.loads(f_before.read())
    f_before.close()

    # Optimize inst_type
    """
    Optimization idea:
        1. Accesses to memory region looks like:
            RVA1 : Access to [REG1 + IMM1]
            RVA2 : Access to [REG2 + IMM2]
            Note: RVA1 is executed prior to RVA2
        2. If both accesses points same area of same object, we do not have to verify accesses from RVA2
            => To avoid redundant checks
        3. How we know whether both accesses points same area of same object?
            => (a) Both accesses points same area(s)
            => condition (a) tells us RVA1 and RVA2 points same *area*
            => (b) We have to ensure REG1 == REG2
            => (c) The value of IMM1/IMM2 are not important, but we have to ensure these are constant
            => conditions (b) and (c) tell us RVA1 and RVA2 points same *object*

    """
    for rva in typed_inst_info.keys():
        typed_inst_info[int(rva)] = typed_inst_info[rva]
        del typed_inst_info[rva]
    rvas = typed_inst_info.keys()
    rvas.sort()
    will_be_removed_rvas = []
    rva1 = None
    for rva1_idx in xrange(len(rvas)):
        print("{0}/{1}".format(rva1_idx, len(rvas)))
        rva1 = rvas[rva1_idx]
        if len(typed_inst_info[rva1]) != 1:
            continue
        for rva2_idx in xrange(rva1_idx+1, len(rvas)):
            rva2 = rvas[rva2_idx]
            if rva2 in will_be_removed_rvas:
                continue
            # We consider instruction with only one mem-ref (for PoC)
            if len(typed_inst_info[rva2]) != 1:
                continue
            assert(rva2 != rva1)
            bbl_rva1 = GetBBLFromEA(rva1)
            if bbl_rva1.startEA > rva2 or rva2 >= bbl_rva1.end_ea:
                # rva1 and rva2 doesn't exist in same bbl
                break
            assert(rva1 <= rva2)

            possible_identifier1 = RetrievePossibleIdentifiersOfRVA(rva1, typed_inst_info)
            possible_identifier2 = RetrievePossibleIdentifiersOfRVA(rva2, typed_inst_info)
            if possible_identifier1 != possible_identifier2:
                # Area identifiers doesn't matched :(
                continue

            sym1 = ExecuteSymbolicSingleStep(rva1)
            sym2 = ExecuteSymbolicSingleStep(rva2)
            reg1 = ExtractMemAccessBaseReg(sym1.keys() + sym1.values())
            reg2 = ExtractMemAccessBaseReg(sym2.keys() + sym2.values())
            if reg1 == None or reg2 == None:
                # Failed to extract reg
                continue
            if reg1 != reg2:
                # Object doesn't matched :(
                continue

            state = INIT_REG
            cur_ea = rva1
            while cur_ea < rva2:
                state = ExecuteSymbolicSingleStep(cur_ea)
                cur_ea = idc.NextHead(cur_ea)
            if ExprId(reg1, 64) in state.keys():
                if state[ExprId(reg1, 64)] != ExprId(reg1 + "_init", 64):
                    # reg has been overwritten
                    continue

            will_be_removed_rvas.append(rva2)
            print("%08x %08x" % (rva1, rva2))
    will_be_removed_rvas = list(set(will_be_removed_rvas))
    will_be_removed_rvas.sort()
    print("{0} / {1}".format(len(will_be_removed_rvas), len(rvas)))

    for will_be_removed_rva in will_be_removed_rvas:
        del typed_inst_info[will_be_removed_rva]
    f_after = open("optimized_{0}".format(path_before), "wb")
    f_after.write(json.dumps(typed_inst_info))
    f_after.close()
    return

if __name__ == "__main__":
    main()