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
idaapi.require("class_analyzer")

CACHED_COMPLETE_VFT_INFO = "%s.cached_vft_info.bintyper" % idaapi.get_root_filename()
CACHED_CLASS_SIZE_INFO = "%s.cached_class_size_info.bintyper" % idaapi.get_root_filename()
CACHED_IDENTIFIER_CONSTRUCTORS_DICT = "%s.cached_identifier_funcs_dict.bintyper" % idaapi.get_root_filename()
CACHED_PARENT_OF_IDENTIFIER_DICT = "%s.cached_parent_of_identifier_dict.bintyper" % idaapi.get_root_filename()
CACHED_AREA_LAYOUT_DICT = "%s.cached_area_layout_dict.bintyper" % idaapi.get_root_filename()

OUTPUT_CLASS_IDENTIFIERS = "%s.output_class_identifiers.bintyper" % idaapi.get_root_filename()
OUTPUT_CLASS_IDENTIFIERS_JSON = OUTPUT_CLASS_IDENTIFIERS + ".json"
OUTPUT_IDENTIFIER_WITH_CONSTRUCTORS = "%s.output_identifier_with_constructors.bintyper" % idaapi.get_root_filename()
OUTPUT_IDENTIFIER_WITH_CONSTRUCTORS_JSON = OUTPUT_IDENTIFIER_WITH_CONSTRUCTORS + ".json"
OUTPUT_IDENTIFIER_WITH_AREA_LAYOUTS = "%s.output_identifier_with_area_layouts.bintyper" % idaapi.get_root_filename()
OUTPUT_IDENTIFIER_WITH_AREA_LAYOUTS_JSON = OUTPUT_IDENTIFIER_WITH_AREA_LAYOUTS + ".json"
OUTPUT_IMAGE_BASE = "%s.image_base.bintyper" % idaapi.get_root_filename()

def DumpParentOfIdentifierDict(parent_of_identifier_dict):
    for identifier in parent_of_identifier_dict:
        print("IDENTIFIER %x" % identifier)
        parent_identifier_info = parent_of_identifier_dict[identifier]
        displacements = parent_identifier_info.keys()
        displacements.sort()
        for displacement in displacements:
            print("%4d => %x" % (displacement, parent_identifier_info[displacement]))
    return

def DumpAreaLayout(class_identifier, layout):
    print("IDENTIFIER [%x]" % class_identifier)
    for k in sorted(layout.keys()):
        sz, parent_identifier = layout[k]
        print("%4x ~ %-4x : %x" % (k, k+sz, parent_identifier))
    return

def main(argv):
    ###########################################################
    # Analyze class information
    ###########################################################
    # Load (cached) vft info
    if not os.path.exists(CACHED_COMPLETE_VFT_INFO):
        complete_vft_dict = class_analyzer.GetCompleteVftDict()
        with open(CACHED_COMPLETE_VFT_INFO, "wb") as f:
            pickle.dump(complete_vft_dict, f)
    else:
        with open(CACHED_COMPLETE_VFT_INFO, "rb") as f:
            complete_vft_dict = pickle.load(f)

    # Load (cached) identifier constructors
    if not os.path.exists(CACHED_IDENTIFIER_CONSTRUCTORS_DICT):
        identifier_constructors_dict = class_analyzer.FindAllConstructors(complete_vft_dict.keys())
        identifier_constructors_dict = class_analyzer.FilterConstructors(identifier_constructors_dict, complete_vft_dict)
        with open(CACHED_IDENTIFIER_CONSTRUCTORS_DICT, "wb") as f:
            pickle.dump(identifier_constructors_dict, f)
    else:
        with open(CACHED_IDENTIFIER_CONSTRUCTORS_DICT, "rb") as f:
            identifier_constructors_dict = pickle.load(f)

    # Analyze inheritance of classes with identifier constructor info
    if not os.path.exists(CACHED_PARENT_OF_IDENTIFIER_DICT):
        parent_of_identifier_dict = class_analyzer.FindParentOfAllIdentifiers(identifier_constructors_dict, complete_vft_dict)
        with open(CACHED_PARENT_OF_IDENTIFIER_DICT, "wb") as f:
            pickle.dump(parent_of_identifier_dict, f)
    else:
        with open(CACHED_PARENT_OF_IDENTIFIER_DICT, "rb") as f:
            parent_of_identifier_dict = pickle.load(f)

    # Load (cached) class size info  
    if not os.path.exists(CACHED_CLASS_SIZE_INFO):
        class_size_info = class_analyzer.GetSizeOfAllClasses(complete_vft_dict, identifier_constructors_dict)
        with open(CACHED_CLASS_SIZE_INFO, "wb") as f:
            pickle.dump(class_size_info, f)
    else:
        with open(CACHED_CLASS_SIZE_INFO, "rb") as f:
            class_size_info = pickle.load(f)

    # Load (cached) area layout dict
    if not os.path.exists(CACHED_AREA_LAYOUT_DICT):
        area_layout_dict = class_analyzer.GetAreaLayouts(complete_vft_dict, parent_of_identifier_dict, class_size_info)
        with open(CACHED_AREA_LAYOUT_DICT, "wb") as f:
            pickle.dump(area_layout_dict, f)
    else:
        with open(CACHED_AREA_LAYOUT_DICT, "rb") as f:
            area_layout_dict = pickle.load(f)

    ###########################################################
    # Export result of analysis to file
    ###########################################################
    # Export class identifiers as json
    with open(OUTPUT_CLASS_IDENTIFIERS_JSON, "wb") as f:
        json.dump(complete_vft_dict.keys(), f)

    # Export class identifier with constructors information as json
    with open(OUTPUT_IDENTIFIER_WITH_CONSTRUCTORS_JSON, "wb") as f:
        def Serializer(obj):
            return obj.__dict__
        json.dump(identifier_constructors_dict, f, default=Serializer)

    # Export class identifier with area layouts information as json
    with open(OUTPUT_IDENTIFIER_WITH_AREA_LAYOUTS_JSON, "wb") as f:
        json.dump(area_layout_dict, f)
    
    f = open(OUTPUT_IMAGE_BASE, "wb")
    f.write(str(idaapi.get_imagebase()))
    f.close()
    return

if __name__ == "__main__":
    start_time = time.time()
    main(sys.argv)
    print("Elapsed time :", time.time()-start_time)