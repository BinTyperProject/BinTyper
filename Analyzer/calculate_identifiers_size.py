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
import json
import pickle
import gc
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
from struct import pack, unpack
from pympler.tracker import SummaryTracker

idaapi.require("class_analyzer")
# idaapi.require("AreaAnalyzer.SSAConverter")
from AreaAnalyzer import SSAConverter
# idaapi.require("AreaAnalyzer.SizeAnalyzer")
from AreaAnalyzer import SizeAnalyzer

CACHED_COMPLETE_VFT_INFO = "pdfium_test.cached_vft_info.bintyper"
CACHED_IDENTIFIER_CONSTRUCTORS_DICT = "pdfium_test.cached_identifier_funcs_dict.bintyper"
CACHED_CLASS_SIZE_INFO = "pdfium_test.cached_class_size_info.bintyper"


converter = SSAConverter.SSAConverter()

def CalculateSizeOfIdentifier(class_identifier, complete_vft_dict, identifier_constructors_dict):
    # if class_identifier != 0x14533a8:
    #     return
    class_size = 8 # due to vft

    # Remove cache
    # gc.collect()
    converter.ssa_cache = {}

    # Handle constructor
    constructors = identifier_constructors_dict.get(class_identifier, [])
    for constructor in constructors:
        func_ea = constructor.func_ea
        # Size filter
        func = idaapi.get_func(func_ea)
        if func.endEA - func.startEA > 1000:
            continue
        sizeanalyzer = SizeAnalyzer.SizeAnalyzer(converter)
        size = sizeanalyzer.GetSizeOf(func_ea)
        class_size = max(class_size, size)

    # Handle methods
    methods = complete_vft_dict[class_identifier][0][2]
    for method_ea in methods:
        # Size filter
        func = idaapi.get_func(method_ea)
        if func.endEA - func.startEA > 1000:
            continue
        sizeanalyzer = SizeAnalyzer.SizeAnalyzer(converter)
        size = sizeanalyzer.GetSizeOf(method_ea)
        class_size = max(class_size, size)

    class_size = SizeAnalyzer.align(class_size, 8)
    print("IDENTIFIER[%x] SIZE[%x]" % (class_identifier, class_size))
    # print("IDENTIFIER[%x] NEW_SIZE[%x] OLD_SIZE[%x]" % (class_identifier, class_size, class_size_info[class_identifier]))
    return class_size

class_size_info = {}

def main(argv):
    global class_size_info

    new_class_size_info = {}

    with open(CACHED_COMPLETE_VFT_INFO, "rb") as f:
        complete_vft_dict = pickle.load(f)
    with open(CACHED_IDENTIFIER_CONSTRUCTORS_DICT, "rb") as f:
        identifier_constructors_dict = pickle.load(f)
    with open(CACHED_CLASS_SIZE_INFO, "rb") as f:
        class_size_info = pickle.load(f)

    class_identifiers = complete_vft_dict.keys()
    for idx in range(len(class_identifiers)):
        print("%d / %d" % (idx, len(class_identifiers)))
        class_identifier = class_identifiers[idx]
        size = CalculateSizeOfIdentifier(class_identifier, complete_vft_dict, identifier_constructors_dict)
        new_class_size_info[class_identifier] = size
    
    with open("output_new_class_size", "wb") as f:
        pickle.dump(new_class_size_info, f)
    return

if __name__ == "__main__":
    main(sys.argv)