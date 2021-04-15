from __future__ import print_function
import ida_ua
import ida_bytes
import idc
import idaapi
import idautils
import os
import sys
import pickle
import time
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
from calculate_identifiers_size import *

machine = Machine('x86_64')
INIT_REG = machine.mn.regs.regs_init

def hx(lst):
    return " ".join("%x" % x for x in lst)

def ALIGN(sz, align_val=8):
    if sz <= 0:
        return sz
    if sz % align_val == 0:
        return sz
    else:
        adder = align_val - (sz % align_val)
        return sz + adder

# Get start/end addresses of read-only sections
def GetROSections():
    seg_addrs_readonly = []
    for seg in idautils.Segments():
        seg_start_ea = idc.SegStart(seg)
        seg_end_ea = idc.SegEnd(seg)
        flags = idc.GetSegmentAttr(seg, idc.SEGATTR_PERM)
        if flags & 6: # Flags 4 means read-only
            seg_addrs_readonly.append([seg_start_ea, seg_end_ea])
    return seg_addrs_readonly

# Get immediate value used as source of MOV/LEA operator
def GetMovedImms():
    imms = []
    for func_ea in idautils.Functions():
        for ins_ea in idautils.FuncItems(func_ea):
            mne = idc.GetMnem(ins_ea)
            if mne not in ["mov", "lea"]:
                continue
            optype = idc.GetOpType(ins_ea, 1)
            if optype == 2 or optype == 5:
                imm = idc.GetOperandValue(ins_ea, 1)
                imms.append(int(imm))
    return imms

# Get all Vtable and its information(xref address)
def GetAllVfts():
    all_vfts = []
    reloc_dict = GetRelocTables()
    ro_sections = GetROSections()
    moved_imms = GetMovedImms()
    moved_imms = list(set(moved_imms))
    moved_imms.sort()

    saved_imms = moved_imms[:]
    for moved_imm in moved_imms:
        # Filter by checking alignment
        if moved_imm % 8 != 0:
            saved_imms.remove(moved_imm)
            continue

        # Filter by checkcing whether imm points ro section
        is_point_ro = False
        for ro_seg_start, ro_seg_end in ro_sections:
            if ro_seg_start <= moved_imm and moved_imm < ro_seg_end:
                is_point_ro = True
                break
        if not is_point_ro:
            saved_imms.remove(moved_imm)
            continue

        # Filter with mandatory field
        offset_to_top = idc.Qword(moved_imm - (8 * 2))
        rtti_val = idc.Qword(moved_imm - (8 * 1))
        if (moved_imm - (8 * 1)) in reloc_dict:
            rtti_val += reloc_dict[moved_imm - (8 * 1)]
        if rtti_val != 0:
            # Bad RTTI
            # print("Bad RTTI", "%08x" % moved_imm)
            # saved_imms.remove(moved_imm)
            # continue
            pass
        if offset_to_top % 8 != 0:
            # Bad OffsetToTop
            # print("Bad OffsetToTop1", "%08x" % moved_imm)
            # saved_imms.remove(moved_imm)
            # continue
            pass

        if not (0xFFFFFFFFFFFF0000 < offset_to_top or offset_to_top == 0):
            # Bad OffsetToTop range
            # print("Bad OffsetToTop2", "%08x" % moved_imm)
            # saved_imms.remove(moved_imm)
            # continue
            pass
        
        if idc.Qword(moved_imm) != 0:
            print("Bad OffsetToTop3", "%08x" % moved_imm)
            saved_imms.remove(moved_imm)
            continue
    moved_imms = saved_imms[:]

    # Filter by checking whether table contains functions
    function_list = []
    for segea in idautils.Segments():
        for funcea in idautils.Functions(segea, idc.SegEnd(segea)):
            function_list.append(funcea)

    moved_imms.sort()
    saved_imms = moved_imms[:]
    for idx in range(len(moved_imms)):
        cur_vfuncs = []
        if idx + 1 < len(moved_imms):
            offset_limit = moved_imms[idx + 1]
        else:
            offset_limit = 0xFFFFFFFFFFFFFFFF
        vft_offset = moved_imms[idx]
        vptr_cur_offset = moved_imms[idx] + 16
        while vptr_cur_offset < offset_limit:
            print("brrr ", "%08x" % vptr_cur_offset, "%08x" % offset_limit)
            if vft_offset+16 != vptr_cur_offset and len(list(idautils.XrefsTo(vptr_cur_offset))):
                # xref exists => area for vptr ends
                break
            maybe_func_ptr = idc.Qword(vptr_cur_offset)
            if vptr_cur_offset in reloc_dict.keys():
                print("ORG %08x" % maybe_func_ptr, "RELOC %08x" % reloc_dict[vptr_cur_offset])
                # maybe_func_ptr += reloc_dict[vptr_cur_offset] # Handle reloc
            print("%08x" % maybe_func_ptr)
            if maybe_func_ptr == 0:
                # It is pure function call: Not-implemented-yet-virtual-method 
                # TODO: Does we have to deal with pure class?
                pass # We do not work for pure function.
            elif maybe_func_ptr in function_list:
                cur_vfuncs.append(maybe_func_ptr)
                print("boliar")
            else:
                break
            vptr_cur_offset += 8

        last_offsettotop = 0
        if len(cur_vfuncs):
            # offset_to_top = idc.Qword(vft_offset - (8 * 2))
            offset_to_top = idc.Qword(vft_offset)
            offset_to_top = GetSignedNumber(offset_to_top, 64)
            if offset_to_top == 0:
                last_offsettotop = 0
            elif offset_to_top > last_offsettotop:
                # Impossible case
                continue
            else:
                last_offsettotop = offset_to_top
            all_vfts.append([
                vft_offset,    # Offset of virtual function table
                offset_to_top, # OffsetToTop
                cur_vfuncs     # Virtual fuction list of table
            ])
    moved_imms = saved_imms[:]
    return all_vfts

def GetCompleteVftDict(all_vfts=None):
    complete_vft_dict = {}
    if all_vfts == None:
        all_vfts = GetAllVfts()

    complete_vft = []
    for single_vft in all_vfts:
        offset_to_top = single_vft[1]
        if offset_to_top == 0:
            if len(complete_vft):
                complete_vft_dict[complete_vft[0][0]] = complete_vft
                complete_vft = []
        complete_vft.append(single_vft)
    if len(complete_vft):
        complete_vft_dict[complete_vft[0][0]] = complete_vft
    return complete_vft_dict

def GetRelocTables():
    reloc_dict = dict()
    sid = idc.GetStrucIdByName('Elf64_Rela')
    for xref in idautils.XrefsTo(sid):
        addr = xref.frm
        # r_offset(8 bytes) + r_info(8 bytes) + r_addend(8 bytes)
        r_offset = idc.Qword(addr + 0)
        r_info = idc.Qword(addr + 8 * 1)
        r_addend = idc.Qword(addr + 8 * 2)
        
        # we only interested in r_info with 8
        if r_info != 8:
            continue

        reloc_dict[r_offset] = r_addend
    return reloc_dict

def GetSignedNumber(number, bitLength):
    mask = (2 ** bitLength) - 1
    if number & (1 << (bitLength - 1)):
        return number | ~mask
    else:
        return number & mask

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

def ExecuteSymbolic(addr, steps, state=INIT_REG):
    state = {}
    for i in range(steps):
        state = ExecuteSymbolicSingleStep(addr, state)
        addr = idc.NextHead(addr)
    return state

def GetBBLFromEA(tgtEA):
    f = idaapi.get_func(tgtEA)
    if not f:
        return None

    fc = idaapi.FlowChart(f, None, 0x4)

    for block in fc:
        if block.startEA <= tgtEA:
            if block.endEA > tgtEA:
                return block
    return None

def GetFunctionFromEA(tgtEA):
    f = idaapi.get_func(tgtEA)
    if not f:
        return None
    else:
        return f
        
def GetSizeOfClassFromInitializer(class_identifier, identifier_constructors_dict, minimum_class_size=-1):
    class_size = minimum_class_size
    if class_identifier not in identifier_constructors_dict:
        return class_size
    class_size = max(class_size, 8)
    constructors = identifier_constructors_dict[class_identifier]
    for constructor in constructors:
        func_ea = constructor.func_ea
        f = GetFunctionFromEA(func_ea)
        state = ExecuteSymbolicAtoB(f.startEA, idc.PrevHead(f.endEA))
        expressions = []
        for target_expr in state.keys():
            if isinstance(target_expr, Expr):
                CollectMemRefExprsFromExpr(target_expr, expressions)
        for single_expr in expressions:
            if isinstance(single_expr, ExprMem):
                if isinstance(single_expr.ptr, ExprId):
                    # [REG] 
                    pass
                elif (isinstance(single_expr.ptr, ExprOp) and single_expr.ptr.op == "+" and
                        isinstance(single_expr.ptr.args[0], ExprId) and 
                        isinstance(single_expr.ptr.args[1], ExprInt)):
                    # [REG + INT]
                    reg = single_expr.ptr.args[0].name.replace("_init", "")
                    offset = int(single_expr.ptr.args[1])
                    ref_size = single_expr.size / 8
                    possible_class_size = offset + ref_size
                    if reg != "RDI":
                        continue
                    class_size = max(possible_class_size, class_size)
    return class_size

def ExecuteSymbolicBBL(bbl_start_ea, state=INIT_REG, start_addr=None, inst_checker_func=None, post_func=None):
    bbl = GetBBLFromEA(bbl_start_ea)
    addr = bbl.startEA
    if start_addr != None and bbl.startEA <= start_addr and start_addr < bbl.endEA:
        addr = start_addr
    while addr < bbl.endEA:
        if inst_checker_func == None or inst_checker_func(addr):
            state = ExecuteSymbolicSingleStep(addr, state)
            if post_func != None:
                state = post_func(addr, state)
        addr = idc.NextHead(addr)
    return state

def ExecuteSymbolicBBLeas(bbl_ea_list, state=INIT_REG, start_addr=None, state_cache={},
                          inst_checker_func=None, post_func=None):
    bbl_idx = 0
    while bbl_idx < len(bbl_ea_list): 
        bbl_tail = tuple(bbl_ea_list[:bbl_idx+1])
        if bbl_tail in state_cache:
            state = state_cache[bbl_tail]
        else:
            state = ExecuteSymbolicBBL(bbl_ea_list[bbl_idx], state, start_addr,
                                       inst_checker_func, post_func)
            state_cache[bbl_tail] = state
        bbl_idx += 1
    return state

def ExecuteSymbolicAtoB(from_addr, to_addr, state=INIT_REG, inst_checker_func=None, post_func=None):
    scope_ranges = [
        # [START_ADDR, END_ADDR]
    ]
    way_addrs = SampleBackwardPath(to_addr, from_addr)
    if way_addrs == None:
        # None means both vft_init_ea and func_ea in same bbl
        way_addrs = [GetBBLFromEA(to_addr).startEA]
    way_addrs.reverse()
    for way_addr in way_addrs:
        way_bbl = GetBBLFromEA(way_addr)
        minimum_from_addr = from_addr
        maximum_to_addr = to_addr
        if way_bbl.startEA <= minimum_from_addr and minimum_from_addr < way_bbl.endEA:
            range_start = minimum_from_addr
        else:
            range_start = way_bbl.startEA
        if way_bbl.startEA <= maximum_to_addr and maximum_to_addr < way_bbl.endEA:
            range_end = maximum_to_addr
        else:
            range_end = way_bbl.endEA
        scope_ranges.append([range_start, range_end])

    for scope_range in scope_ranges:
        scope_start_addr, scope_end_addr = scope_range
        cur_addr = scope_start_addr
        while cur_addr < scope_end_addr:
            if inst_checker_func == None or inst_checker_func(cur_addr):
                state = ExecuteSymbolicSingleStep(cur_addr, state)
                if post_func != None:
                    state = post_func(cur_addr, state)
            cur_addr = idc.NextHead(cur_addr)
    return state

def SampleBackwardPath(target_bbl_start_ea, addr_limit_front=None, history=[], finished={}):
    bbl = GetBBLFromEA(target_bbl_start_ea)
    history = history + [bbl.startEA]

    # Check whether it has no future
    if bbl.startEA in finished:
        return None

    # Check either it reaches end-point
    if len(list(bbl.preds())) == 0 or (bbl.startEA <= addr_limit_front and addr_limit_front < bbl.endEA):
        return history

    # Traverse childs
    for pred_bbl in bbl.preds():
        if pred_bbl.startEA not in history:
            ret = SampleBackwardPath(pred_bbl.startEA, addr_limit_front, history, finished)
            if ret != None:
                return ret
    finished[bbl.startEA] = True
    return None

def BackwardAnalysis(target_addr, target_reg, start_addr=None, state_cache={}):
    possible_vals = []

    # Obtain backward path
    # print("calculate the backward path")
    target_bbl = GetBBLFromEA(target_addr)
    backward_path = SampleBackwardPath(target_bbl.startEA, start_addr)
    backward_path = backward_path[1:]
    backward_path.reverse()

    # Prepate state
    # print("pre-execute")
    state = ExecuteSymbolicBBLeas(backward_path, state_cache=state_cache)
    # print("execute ok")
    # state = ExecuteSymbolicBBLs(backward_path)

    addr = target_bbl.startEA
    if start_addr != None and target_bbl.startEA <= start_addr and start_addr < target_bbl.endEA:
        addr = start_addr
    while addr < target_addr:
        state = ExecuteSymbolicSingleStep(addr, state)
        addr = idc.NextHead(addr)
    possible_val = None
    if target_reg in state:
        possible_val = state[target_reg]
        # Minimalize
        while possible_val in state.keys():
            possible_val = state[possible_val]
    return [possible_val]

def CollectMemRefExprsFromExpr(expr, out):
    if isinstance(expr, ExprMem):
        if isinstance(expr.ptr, ExprId):
            out.append(expr)
        if isinstance(expr.ptr, ExprOp) and expr.ptr.op == "+":
            if isinstance(expr.ptr.args[0], ExprId) and isinstance(expr.ptr.args[1], ExprInt):
                out.append(expr)
    if isinstance(expr, ExprCompose):
        for i in expr.args:
            CollectMemRefExprsFromExpr(i, out)
    for attr_name in expr.__slots__:
        attr_value = getattr(expr, attr_name)
        if isinstance(attr_value, Expr):
            CollectMemRefExprsFromExpr(attr_value, out)
    return

def CollectReferences(method_addr, target_reg_name, minimum_class_size):
    mem_references_by_size = {}
    work_list = [method_addr] 
    visited_block = []
    while len(work_list):
        cur_ea = work_list.pop()
        bbl = GetBBLFromEA(cur_ea)
        if bbl.startEA not in visited_block:
            visited_block.append(bbl.startEA)
        for succs in bbl.succs():
            if succs.startEA < GetFunctionFromEA(method_addr).startEA or GetFunctionFromEA(method_addr).endEA <= succs.startEA:
                continue
            if succs.startEA not in visited_block:
                work_list.append(succs.startEA)

        # Find member-reference-like symolic state
        while cur_ea < bbl.endEA:
            state = ExecuteSymbolicSingleStep(cur_ea)

            expressions = []
            for single_expr in state.keys() + state.values():
                CollectMemRefExprsFromExpr(single_expr, expressions)

            for single_expr in expressions:
                if isinstance(single_expr, ExprMem):
                    if isinstance(single_expr.ptr, ExprId):
                        # [REG] 
                        pass
                    elif (isinstance(single_expr.ptr, ExprOp) and single_expr.ptr.op == "+" and
                            isinstance(single_expr.ptr.args[0], ExprId) and 
                            isinstance(single_expr.ptr.args[1], ExprInt)):
                        # [REG + INT]
                        reg = single_expr.ptr.args[0].name.replace("_init", "")
                        offset = int(single_expr.ptr.args[1])
                        ref_size = single_expr.size / 8
                        possible_class_size = offset + ref_size
                        if possible_class_size <= minimum_class_size:
                            continue
                        if reg in ["RSP", "RBP"]:
                            continue
                        if possible_class_size not in mem_references_by_size:
                            mem_references_by_size[possible_class_size] = []
                        mem_references_by_size[possible_class_size].append([
                            cur_ea, # CUR_EA
                            reg,
                            method_addr,
                            target_reg_name
                        ])
            cur_ea = idc.NextHead(cur_ea)
    return mem_references_by_size

def AnalyzeMaximumSizeFromReferences(mem_references_by_size, class_size):
    state_cache = {}
    possible_class_sizes = mem_references_by_size.keys()
    possible_class_sizes.sort(reverse=True)
    for possible_class_size in possible_class_sizes:
        if possible_class_size > 0x10000: continue
        if possible_class_size <= class_size: continue
        for cur_ea, reg, addr_front_limit, holding_vft_reg in mem_references_by_size[possible_class_size]:
            sources = BackwardAnalysis(cur_ea, ExprId(reg, 64), addr_front_limit, state_cache)

            for source in sources:
                if not isinstance(source, ExprId):
                    continue
                name = source.name.replace("_init", "")
                if name == holding_vft_reg:
                    class_size = max(class_size, possible_class_size)
                    class_size = ALIGN(class_size, 8)
    return class_size

def GetSizeOfClassFromMethod(method_addr, target_reg_name="RDI", minimum_class_size=8):
    class_size = minimum_class_size
    mem_references_by_size = {}

    mem_references_by_size = CollectReferences(method_addr, target_reg_name, class_size)
    class_size = AnalyzeMaximumSizeFromReferences(mem_references_by_size, class_size)
    return class_size

def GetSizeOfClassFromIdentifierMethods(class_identifier, complete_vft_dict, minimum_class_size=8):
    class_size = minimum_class_size
    methods = complete_vft_dict[class_identifier][0][2] # [0] indicates primary vft and [2] indiciates virtual methods
    i = 0
    for method in methods:
        i += 1
        class_size = max(class_size, GetSizeOfClassFromMethod(method, minimum_class_size=class_size))
        class_size = ALIGN(class_size, 8)
    return class_size

def GetSizeOfClass(class_identifier, complete_vft_dict, identifier_constructors_dict=None, minimum_class_size=-1):
    class_size = minimum_class_size
    class_size = max(class_size, GetSizeOfClassFromIdentifierMethods(class_identifier, complete_vft_dict, class_size))
    if identifier_constructors_dict != None:
        class_size = max(class_size, GetSizeOfClassFromInitializer(class_identifier, identifier_constructors_dict, class_size))
    class_size = ALIGN(class_size, 8)
    return class_size

def GetSizeOfAllClasses(complete_vft_dict, identifier_constructors_dict):
    class_size_info = {}

    # Caching
    SIZE_CACHE = "temp_sizecache"
    if os.path.exists(SIZE_CACHE):
        with open(SIZE_CACHE, "rb") as f:
            class_size_info = pickle.load(f)

    i = 0
    for class_identifier in complete_vft_dict.keys():
        i += 1
        print("Processing %d of %d" % (i, len(complete_vft_dict)), time.ctime())
        sys.stdout.write("Identifier [%x] " % class_identifier)
        # class_size = GetSizeOfClass(class_identifier, complete_vft_dict, identifier_constructors_dict)
        if class_identifier not in class_size_info:
            class_size = CalculateSizeOfIdentifier(class_identifier, complete_vft_dict, identifier_constructors_dict)
            class_size_info[class_identifier] = class_size
        class_size = class_size_info[class_identifier]
        sys.stdout.write("Size from all : %x\n" % class_size)

        # Caching
        with open(SIZE_CACHE, "wb") as f:
            pickle.dump(class_size_info, f)
    return class_size_info

class IdentifierConstructor(object):
    def __init__(self, func_ea, class_identifier, vft_init_ea=None):
        self.func_ea = func_ea
        self.class_identifier = class_identifier
        self.vft_init_ea = vft_init_ea
        return

    def __repr__(self):
        return "IDENTIFIER[%x] FUNC_EA[%x] VFT_INIT_EA[%x]" % (self.class_identifier, self.func_ea, self.vft_init_ea)

def FindConstructors(class_identifier, class_identifier_list, identifier_to_constructors_dict, solved=[]):
    state_cache = {}
    for xref in idautils.XrefsTo(class_identifier):
        func = GetFunctionFromEA(xref.frm)
        if not func:
            continue
        if func.startEA in solved:
            # Already processed
            continue

        def AssignChecker(addr):
            mne = idc.GetMnem(addr)
            if mne in ["mov", "lea"]:
                return True
            else:
                return False

        value_at_rdi_info = []
        def ValueAtRDIPtrTracker(addr, state):
            dest_mem = ExprMem(ExprId("RDI_init", 64), 64)
            if dest_mem in state and isinstance(state[dest_mem], ExprInt):
                value_at_rdi_info.append([addr, int(state[dest_mem])])
                new_state = state.copy()
                del new_state[dest_mem]
                return new_state
            return state

        ways_from_start_to_end = SampleBackwardPath(idc.PrevHead(func.endEA), func.startEA)
        ways_from_start_to_end.reverse()
        state = ExecuteSymbolicBBLeas(ways_from_start_to_end, state_cache=state_cache,
                                      inst_checker_func=AssignChecker, post_func=ValueAtRDIPtrTracker)
        if len(value_at_rdi_info):
            writer_addr, last_written_identifier = value_at_rdi_info[-1]
            if last_written_identifier in class_identifier_list:
                if last_written_identifier not in identifier_to_constructors_dict:
                    identifier_to_constructors_dict[last_written_identifier] = []
                vft_init_ea = writer_addr
                constructor = IdentifierConstructor(func.startEA, last_written_identifier, vft_init_ea)
                identifier_to_constructors_dict[last_written_identifier].append(constructor)
                solved.append(func.startEA)
    return

def FindAllConstructors(class_identifier_list):
    identifier_to_constructors_dict = {}
    solved = []
    i = 0
    # Find possible constructors
    for class_identifier in class_identifier_list:
        i += 1
        # if class_identifier not in [0x145E3A0]: continue
        print("%d/%d %x" % (i, len(class_identifier_list), class_identifier))
        FindConstructors(class_identifier, class_identifier_list, identifier_to_constructors_dict, solved)
    return identifier_to_constructors_dict

# Filter possible constructors which may be not constructor actually (e.g. destructor)
def FilterConstructors(old_identifier_constructors_dict, complete_vft_dict):
    identifier_constructors_dict = old_identifier_constructors_dict.copy()
    bad_functions = [
    ]

    # Prepare bad function list
    for ea in idautils.Segments():
        for funcaddress in idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea)):
            f_name = idc.GetFunctionName(funcaddress)
            f_name_demangled = idc.demangle_name(f_name, idc.GetLongPrm(idc.INF_SHORT_DN))
            if f_name_demangled != None:
                f_name = f_name_demangled
            if "(" in f_name:
                tmp_name = f_name[:f_name.find("(")]
            else:
                tmp_name = f_name
            if "free" in tmp_name.lower():
                bad_functions.append(funcaddress)
            elif "operator delete" in tmp_name.lower():
                bad_functions.append(funcaddress)

    # Build virtual method list
    virtual_methods = []
    for vft_infos in complete_vft_dict.values():
        for vft_info in vft_infos:
            virtual_methods += vft_info[2]

    changed = True
    while changed:
        changed = False
        for class_identifier, constructors in identifier_constructors_dict.items():
            new_constructors = []
            for constructor in constructors:
                # Check virtualized function. Which means it is destructor
                if constructor.func_ea in virtual_methods:
                    bad_functions.append(constructor.func_ea)
                    changed = True
                    continue
                # Count references of bad functions
                ref_count = 0
                badref_count = 0
                f = idaapi.get_func(constructor.func_ea)
                fc = idaapi.FlowChart(f, None, 0x4)
                for bbl in fc:
                    cur_ea = bbl.startEA
                    while cur_ea < bbl.endEA:
                        for ref in idautils.XrefsFrom(cur_ea):
                            if f.startEA <= ref.to and ref.to < f.endEA:
                                continue
                            ref_count += 1
                            if ref.to in bad_functions:
                                badref_count += 1
                        cur_ea = idc.NextHead(cur_ea)
                bad_percent = (badref_count*100.0)/ref_count
                if 50.0 <= bad_percent:
                    bad_functions.append(constructor.func_ea)
                    changed = True
                    continue
                # Okay. It is not destructor!
                new_constructors.append(constructor)
            identifier_constructors_dict[class_identifier] = new_constructors
    return identifier_constructors_dict

def FindParentOfIdentifiers(target_constructor, identifier_constructors_dict, complete_vft_dict):
    parent_identifier_info = {}
    print("Analyze class identifier %x func_ea %x" % (target_constructor.class_identifier, target_constructor.func_ea))
    # Build dictionary for matching function-ea to constructor
    func_ea_to_constructor = {}
    for tmp_constructors in identifier_constructors_dict.values():
        for tmp_constructor in tmp_constructors:
            tmp_identifier_func_ea = tmp_constructor.func_ea
            if tmp_identifier_func_ea not in func_ea_to_constructor:
                func_ea_to_constructor[tmp_identifier_func_ea] = tmp_constructor
            else:
                raise Exception("Check this case",
                                    func_ea_to_constructor[tmp_identifier_func_ea],
                                    "and",
                                    tmp_constructor)
                # Already exists. Check init_ea and replace func within higher init_ea
                if (func_ea_to_constructor[tmp_identifier_func_ea].vft_init_ea <
                    tmp_constructor.vft_init_ea):
                    func_ea_to_constructor[tmp_identifier_func_ea] = tmp_constructor

    # Calculate ranges between target function start and target vft init ea
    scope_ranges = [
        # [START_ADDR, END_ADDR]
    ]
    way_addrs = SampleBackwardPath(target_constructor.vft_init_ea, target_constructor.func_ea)
    if way_addrs == None:
        # None means both vft_init_ea and func_ea in same bbl
        way_addrs = [GetBBLFromEA(target_constructor.vft_init_ea).startEA]
    for way_addr in way_addrs:
        way_bbl = GetBBLFromEA(way_addr)
        minimum_from_addr = target_constructor.func_ea
        maximum_to_addr = target_constructor.vft_init_ea
        if way_bbl.startEA <= minimum_from_addr and minimum_from_addr < way_bbl.endEA:
            range_start = minimum_from_addr
        else:
            range_start = way_bbl.startEA
        if way_bbl.startEA <= maximum_to_addr and maximum_to_addr < way_bbl.endEA:
            range_end = maximum_to_addr
        else:
            range_end = way_bbl.endEA
        scope_ranges.append([range_start, range_end])

    # Find constructor calls and class identifier references insides of ranges
    # **NOTE** Current identifier-related operations should be ignored

    # Obtain possible OffsetToTop values from target complete vft
    possible_offsettotops = []
    target_complete_vft = complete_vft_dict[target_constructor.class_identifier]
    for partial_vft_info in target_complete_vft:
        _, neg_offsettotop, _ = partial_vft_info
        offsettotop = abs(neg_offsettotop)
        possible_offsettotops.append(offsettotop)
    possible_offsettotops = list(set(possible_offsettotops))
    possible_offsettotops.sort()

    # Traverse references among scope_ranges
    for scope_range in scope_ranges:
        range_start, range_end = scope_range
        cur_ea = range_start
        while cur_ea < range_end:
            for ref in idautils.XrefsFrom(cur_ea):
                written_ptr = None
                # Check reference for vft(class identifier)
                if ref.to in complete_vft_dict:
                    if ref.to == target_constructor.class_identifier:
                        continue
                    print("VFT reference to %x from %x" % (ref.to, ref.frm))

                    ref_vft = ref.to
                    def ExecuteCond(addr):
                        if len(saved_point) == 0:
                            return True
                        else:
                            return False
                    saved_point = [] # Trick
                    def WrittenPointTracker(addr, state):
                        if ExprInt(ref_vft, 64) in state.values():
                            for k, v in state.items():
                                if (v == ExprInt(ref_vft, 64) and 
                                    isinstance(k, ExprMem)):
                                    saved_point.append(k)
                        return state

                    state = ExecuteSymbolicAtoB(target_constructor.func_ea, target_constructor.vft_init_ea,
                                                inst_checker_func=ExecuteCond, post_func=WrittenPointTracker)
                    if len(saved_point):
                        saved_point = saved_point[0] # Trick
                        assert(isinstance(saved_point, ExprMem))
                        saved_point = saved_point.ptr
                        written_ptr = saved_point
                        possible_parent_identifier = ref_vft
                # Check reference for constructor
                elif ref.to in func_ea_to_constructor:
                    possible_constructor = func_ea_to_constructor[ref.to]
                    if possible_constructor.class_identifier == target_constructor.class_identifier:
                        continue
                    print("Constructor reference to %x from %x" % (possible_constructor.class_identifier, ref.frm))
                    state = ExecuteSymbolicAtoB(target_constructor.func_ea, ref.frm)
                    if ExprId("RDI", 64) in state:
                        written_ptr = state[ExprId("RDI", 64)]
                        possible_parent_identifier = possible_constructor.class_identifier

                displacement = -1
                if written_ptr != None:
                    # Calculate difference between written_ptr and RDI_init
                    # and fill the return value
                    if written_ptr == ExprId("RDI_init", 64):
                        displacement = 0
                    elif (isinstance(written_ptr, ExprOp) and written_ptr.op == "+" and
                          written_ptr.args[0] == ExprId("RDI_init", 64) and isinstance(written_ptr.args[1], ExprInt)):
                        displacement = int(written_ptr.args[1])
                    if displacement != -1:
                        if displacement in possible_offsettotops:
                            if displacement in parent_identifier_info:
                                # Multiple initialization on same displacement
                                # it means multiple inlined constructor(inlined constructor of inlined constructor)
                                pass
                                # print("OLD", parent_identifier_info[displacement])
                                # print("NEW", possible_parent_identifier)
                            parent_identifier_info[displacement] = possible_parent_identifier
            cur_ea = idc.NextHead(cur_ea)
    return parent_identifier_info

def FindParentOfAllIdentifiers(identifier_constructors_dict, complete_vft_dict):
    parent_of_identifier_dict = {}
    for class_identifier in identifier_constructors_dict:
        constructors = identifier_constructors_dict[class_identifier]
        # if class_identifier != 0x1423490: continue
        for target_constructor in constructors:
            parent_of_identifier_info = FindParentOfIdentifiers(target_constructor, identifier_constructors_dict,
                                                                complete_vft_dict)
            if not len(parent_of_identifier_info.keys()):
                continue
            if target_constructor.class_identifier in parent_of_identifier_dict:
                if parent_of_identifier_dict[target_constructor.class_identifier] != parent_of_identifier_info:
                    # This should not be happened. To avoid it we need to filter destructor
                    print("Invalid parent identifier: ",
                                    parent_of_identifier_dict[target_constructor.class_identifier],
                                    "and",
                                    parent_of_identifier_info)
            # Add to dictionary once parent identifier exists only
            parent_of_identifier_dict[target_constructor.class_identifier] = parent_of_identifier_info
    return parent_of_identifier_dict

def GetAreaLayout(class_identifier, parent_of_identifier_dict, class_size_info):
    latest_offset = 0
    area_layout = {}

    if class_identifier not in class_size_info:
        # Cannot analyze size of current identifier
        return {}
    maximum_size = class_size_info[class_identifier]
    if class_identifier in parent_of_identifier_dict:
        # It has parent identifiers
        displacements = sorted(parent_of_identifier_dict[class_identifier].keys())
        i = 0
        for i in range(len(displacements)):
            if i + 1 < len(displacements):
                parent_identifier = parent_of_identifier_dict[class_identifier][displacements[i]]
                sz = displacements[i + 1] - displacements[i]
            else:
                parent_identifier = parent_of_identifier_dict[class_identifier][displacements[i]]
                if parent_identifier not in class_size_info:
                    # Cannot analyze size of parent identifier
                    return {}
                sz = class_size_info[parent_identifier]
            area_layout[displacements[i]] = [sz, parent_identifier]
            latest_offset = displacements[i]+sz
    # Remain space is for derived class identifier
    if latest_offset < maximum_size:
        area_layout[latest_offset] = [maximum_size - latest_offset, class_identifier]
    return area_layout

def GetAreaLayouts(complete_vft_dict, parent_of_identifier_dict, class_size_info):
    area_layout_dict = {}
    for class_identifier in complete_vft_dict.keys():
        area_layout_dict[class_identifier] = GetAreaLayout(class_identifier, parent_of_identifier_dict, class_size_info)
    return area_layout_dict
