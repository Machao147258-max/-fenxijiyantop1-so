#!/bin/sh
# so_5min.sh —— 5 分钟静态定面
# 用法: sh so_5min.sh target.so
T=${1:?so}
echo "== file =="; file "$T"
echo "== header (Class/Machine) =="; readelf -h "$T" | grep -E "Class|Machine"
echo "== sections =="; readelf -S "$T" | grep -E "text|dynsym|init_array|rodata"
echo "== dynsym (Java_ 接缝) =="; readelf --dyn-syms "$T" | grep Java_ | head -40
echo "== init_array =="; readelf -d "$T" | grep INIT_ARRAY
echo "== 特征串 =="; strings -a "$T" | grep -iE "key|salt|cipher|aes|gcm|sm4|frida|assets|/proc/|ptrace" | head -40
echo "== 内联 svc 条数 (0=全 libc / >0=有绕过) =="; objdump -d "$T" 2>/dev/null | grep -c "svc"
