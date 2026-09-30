#!/usr/bin/env python3
# qiling_automap.py —— 让库"跑到底": auto-map 未映射页
# 库 init 常因缺环境早崩 (UC_ERR_FETCH/WRITE_UNMAPPED); 自动映射缺页继续跑
# 效果: JNI_OnLoad 从"早崩"到"跑到底", 触发真正行为(读文件 / 进 syscall 引擎)
# 依赖: Qiling (源码版) —— from qiling import Qiling
import sys
sys.path.insert(0, r'<你的qiling路径>')      # 改成 qiling 源码路径
from qiling import Qiling
from qiling.const import QL_VERBOSE
from unicorn import UC_HOOK_MEM_UNMAPPED

SO_DIR = './rootfs'

def hook_unmapped(uc, access, address, size, value, user_data):
    page = address & ~0xfff
    try:
        uc.mem_map(page, 0x1000)
        print('[automap] mapped page %#x' % page)
    except Exception as e:
        print('[automap] map fail %#x: %s' % (page, e))
    return True

def main():
    ql = Qiling([SO_DIR + '/libtarget.so'], SO_DIR, verbose=QL_VERBOSE.DEFAULT)
    ql.uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)
    ql.run()

if __name__ == '__main__':
    main()
