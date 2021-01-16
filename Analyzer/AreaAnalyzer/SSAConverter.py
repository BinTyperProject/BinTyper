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
from miasm.arch.x86.regs import attrib_to_regs 
from miasm.expression.expression import *
from miasm.expression.simplifications import *
from miasm.expression.simplifications_cond import *
from miasm.core.bin_stream_ida import bin_stream_ida
from miasm.core.asmblock import log_asmblock, AsmCFG
from miasm.analysis.ssa import SSADiGraph
from miasm.core.cpu import *
from miasm.ir.ir import IRBlock, AssignBlock
from miasm.analysis.simplifier import IRCFGSimplifierCommon, IRCFGSimplifierSSA

def DumpIRCFG(ircfg):
    for lbl, irblock in ircfg.blocks.items():
        print(irblock.to_string(ircfg.loc_db))
    return

class AssignBlockWithState(AssignBlock):
    def __init__(self, original_assignblk, state):
        self.__slots__ = original_assignblk.__slots__[:]
        self.__slots__ += ["state"]
        self.state = state
        for i in original_assignblk.__slots__:
            setattr(self, i, getattr(original_assignblk, i))

        self.state = state
        return

class SSAConverter(object):
    def __init__(self):
        self.machine = Machine('x86_64')
        self.dis_engine, self.ira = self.machine.dis_engine, self.machine.ira
        self.bs = bin_stream_ida()
        self.mdis = self.dis_engine(self.bs)

        self.ssa_cache = {}
        self.ssa_with_state_cache = {}
        return

    def Analyze(self, addr, deep=False):
        todo_list = []
        if addr in self.ssa_cache:
            return self.ssa_cache[addr]

        asmcfg = self.mdis.dis_multiblock(addr)

        ira = self.machine.ira(asmcfg.loc_db)
        try:
            ircfg = ira.new_ircfg_from_asmcfg(asmcfg)
        except:
            # Failed on converting
            self.ssa_cache[addr] = None
            return None

        modified = True
        while modified:
            modified = ircfg.simplify(expr_simp)

        ssa = SSADiGraph(ircfg)
        ssa.transform(asmcfg.loc_db.get_offset_location(addr))

        # for lbl, irblock in ircfg.blocks.items():
        #     print(irblock.to_string(ircfg.loc_db))

        if deep:
            for lbl, irblock in ircfg.blocks.items():
                for blk in irblock.assignblks:
                    for val in blk.values():
                        if (isinstance(val, ExprOp)
                                and val.op == "call_func_ret"
                                and isinstance(val.args[0], ExprLoc)):
                            callee_addr = asmcfg.loc_db.get_location_offset(val.args[0].loc_key)

                            if callee_addr not in todo_list:
                                todo_list.append(callee_addr)

        self.ssa_cache[addr] = ircfg

        if deep:
            # Recursively analyze functions which are called by initial target function
            for callee_addr in todo_list:
                self.Analyze(callee_addr, deep)
        return ircfg

    def InitializeState(self, label, state_of_label):
        initial_state = {}
        for reg_id in attrib_to_regs[64]:
            initial_state[reg_id] = reg_id

        state_of_label[label] = initial_state
        return

    def AnalyzeWithState(self, addr, deep=False):
        if addr in self.ssa_with_state_cache:
            return self.ssa_with_state_cache[addr]
        ircfg = self.Analyze(addr, deep)
        if not ircfg:
            self.ssa_with_state_cache[addr] = None
            return None

        head = ircfg.loc_db.get_offset_location(addr)
        visited = []

        # Set initial state of head
        state_of_label = {} # label:state
        self.InitializeState(head, state_of_label)

        todo_labels = [head]
        while todo_labels:
            lbl = todo_labels.pop(0)
            if lbl in visited:
                continue
            else:
                visited.append(lbl)
            irblock = ircfg.blocks[lbl]

            current_state = state_of_label[lbl]

            # Replace assignblocks to assignblocks with state
            new_assignblks = []
            for assignblk in irblock.assignblks:
                # Check assignblk is for phi-related blk
                is_phiblk = False
                if len(assignblk.values()):
                    sample_expr = assignblk.values()[0]
                    if isinstance(sample_expr, ExprOp) and sample_expr.op == "Phi":
                        is_phiblk = True
                
                if not is_phiblk:
                    new_assignblk = AssignBlockWithState(assignblk, current_state.copy())
                else:
                    new_assignblk = assignblk
                new_assignblks.append(new_assignblk)

                # Process assignblocks and update current state
                dsts = assignblk.keys()
                for dst in dsts:
                    if not isinstance(dst, ExprId):
                        continue
                    if dst.name == "IRDst":
                        continue
                    assert("." in dst.name) 
                    org_name = dst.name[:dst.name.find(".")]
                    org_expr = ExprId(org_name, dst.size)
                    assert(org_expr in current_state)
                    current_state[org_expr] = dst

            irblock._assignblks = tuple(new_assignblks)

            # Add successors to todo list and update its initial state
            successor_labels = ircfg.successors(lbl)
            todo_labels += filter(lambda x: x not in visited, successor_labels)
            # Update state of successors label with latest current state
            for successor_label in successor_labels:
                state_of_label[successor_label] = current_state.copy()
        
        self.ssa_with_state_cache[addr] = ircfg
        return ircfg

def main():
    # addr = 0x00000001C006BD60
    # converter = SSAConverter()
    # ircfg = converter.AnalyzeWithState(addr, deep=False)
    # DumpIRCFG(ircfg)
    return

if __name__ == "__main__":
    main()