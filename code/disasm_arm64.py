#!/usr/bin/env python3
# disasm_arm64.py —— capstone 定点反汇编
# 用法: python disasm_arm64.py target.so <hex_offset> <hex_len>
#   例: python disasm_arm64.py libx.so 0x14000 0x200
import sys
import capstone

if len(sys.argv) < 4:
    print("usage: python disasm_arm64.py target.so <hex_offset> <hex_len>")
    sys.exit(1)

path = sys.argv[1]
off = int(sys.argv[2], 16)
ln = int(sys.argv[3], 16)

data = open(path, 'rb').read()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True
for i in md.disasm(data[off:off + ln], off):
    print("%#x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
