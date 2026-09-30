# ida_xref.py —— IDA headless 定点取证: 关键串 -> xref -> 函数 -> 反编译
# 跑法: idat -A -S"ida_xref.py <out_dir>" target.so
#   Linux: idat -A -S"ida_xref.py ./out" target.so
#   Win  : idat.exe -A -S"ida_xref.py C:\out" C:\target.so
# 产出: 命中串 -> 函数名@地址(dump 到 stdout) + 每个函数的反编译 decomp_<addr>.txt
import sys
import os
import idautils
import ida_funcs
import ida_hexrays
import ida_auto
import idc

OUT = sys.argv[1] if len(sys.argv) > 1 else "."

# 关键串: 按目标改 (协议/证书/固定/命令 等特征)
KEYS = [
    "kproxy", "pin-sha256", "known-pins", "served-certificate-chain",
    "verifyServerCertificates", "x-aegon-skip-cert-verify",
    "public_key_hashes", "BlockedSPKIs",
]

def main():
    ida_auto.auto_wait()                     # 等 IDA 自动分析完成
    if OUT and not os.path.isdir(OUT):
        try: os.makedirs(OUT)
        except Exception: pass
    for s in idautils.Strings():             # 遍历所有字符串
        try:
            txt = str(s)
        except Exception:
            continue
        if any(k in txt for k in KEYS):
            for xr in idautils.XrefsTo(s.ea):  # 反查引用它的代码位置
                f = ida_funcs.get_func(xr.frm)
                if not f:
                    continue
                print("STR %r -> FUNC %s @0x%x" % (txt[:60], ida_funcs.get_func_name(f.start_ea), f.start_ea))
                try:
                    cf = ida_hexrays.decompile(f.start_ea)
                    if cf:
                        open(os.path.join(OUT, "decomp_%x.txt" % f.start_ea), "w", encoding="utf-8").write(str(cf))
                except Exception as e:
                    print("  decomp fail @0x%x: %s" % (f.start_ea, e))
    idc.qexit(0)                             # 跑完退出 (headless 模式必须)

if __name__ == "__main__":
    main()
