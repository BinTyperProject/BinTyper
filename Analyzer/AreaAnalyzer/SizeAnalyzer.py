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

def align(val, align_size):
    if val % align_size:
        return val + (align_size - (val % align_size))
    else:
        return val

def TraverseExpr(expr, callbacks):
    # Callback from itself
    matched_callback = callbacks.get(expr.__class__.__name__, None)
    if matched_callback:
        matched_callback(expr)
        
    # Callback from childs
    for attr_name in expr.__slots__:
        attr_value = getattr(expr, attr_name)
        if not isinstance(attr_value, Expr):
            continue

        # Call callback
        matched_callback = callbacks.get(attr_value.__class__.__name__, None)
        if matched_callback:
            matched_callback(expr)

        # Traverse recursively
        TraverseExpr(attr_value, callbacks)
    return

class SizeAnalyzer(object):
    def __init__(self, converter):
        self.converter = converter
        self.maximum_size = -1
        return

    def IsPhiExpr(self, expr):
        return (isinstance(expr, ExprOp) and expr.op == "Phi")

    def GetMaxiumumAccessedOffset(self, func_addr, original_reg):
        ircfg = self.converter.Analyze(func_addr)
        if not ircfg:
            return 0

        # Step1. Find aliased reg of original reg
        target_regs = [original_reg]
        found = True
        while found:
            found = False
            for lbl, irblock in ircfg.blocks.items():
                for assignblk in irblock.assignblks:
                    for dst, src in assignblk.items():
                        if not isinstance(dst, ExprId):
                            continue
                        # Pure-assignment
                        if src in target_regs:
                            if dst not in target_regs:
                                target_regs.append(dst)
                                found = True
                        # Phi
                        elif self.IsPhiExpr(src) and len(set(target_regs) & set(src.args)):
                            if dst not in target_regs:
                                target_regs.append(dst)
                                found = True

        # Step2. Calculate maxium accessed size from both original reg and aliased regs
        def handleExprMem(expr):
            if not isinstance(expr, ExprMem):
                return
            # print(expr, type(expr))
            size = expr.size
            size = align(size, 8)
            size_bytes = size / 8
            expr_ptr = expr.ptr
            # @size[@reg]
            if expr_ptr in target_regs:
                ptr = expr_ptr
                offset = 0
                self.maximum_size = max(self.maximum_size, offset + size_bytes)
            # @size[@reg+@offset]
            if isinstance(expr_ptr, ExprOp):
                if expr_ptr.op not in ["+", "-"]:
                    return
                ptr = expr_ptr.args[0]
                if ptr not in target_regs:
                    return
                offset = expr_ptr.args[1]
                if not isinstance(offset, ExprInt):
                    return
                offset = int(offset)
                if expr_ptr.op == "+" and offset > 0x100000:
                    return
                elif expr_ptr.op == "-" and offset > 0x100000:
                    offset = (1 << 64) - offset
                self.maximum_size = max(self.maximum_size, offset + size_bytes)
            return
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock.assignblks:
                for expr in (assignblk.keys() + assignblk.values()):
                    expr = expr_simp(expr)
                    TraverseExpr(expr, {"ExprMem": handleExprMem})
        return self.maximum_size

    def GetSizeOf(self, func_addr):
        return self.GetMaxiumumAccessedOffset(func_addr, ExprId("RDI", 64))

def main():
    converter = SSAConverter.SSAConverter()
    sizeanalyzer = SizeAnalyzer(converter)
    size = sizeanalyzer.GetSizeOf(0x0000000001148360)
    print(size)
    return

if __name__ == "__main__":
    main()