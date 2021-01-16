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
from struct import *

VTABLE_NAME_PREFIX = "`vtable for'"

vft_list = {}
for addr, name in idautils.Names():
    demangled_name = idc.demangle_name(name, idc.GetLongPrm(idc.INF_SHORT_DN))
    if demangled_name != None:
        name = demangled_name
    # print("%x" % addr, name)

    if not name.startswith(VTABLE_NAME_PREFIX):
        continue
    name = name.replace("`anonymous namespace'", "(anonymousnamespace)")
    addr = int(addr) + 0x10

    print(name)
    vft_list[addr] = name 

f = open("{0}.vft_set.bintyper.json".format(idaapi.get_root_filename()), "wb")
unique_vft_set = sorted(list(set(vft_list.keys())))
# f.write(pack("<Q", len(unique_vft_set)))
# for vft in unique_vft_set:
#     f.write(pack("<Q", vft))
f.write(json.dumps({"vft_set": unique_vft_set}))
f.close()