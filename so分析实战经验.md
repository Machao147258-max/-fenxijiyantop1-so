# SO 分析实战经验：静态定面 · 黑盒转白盒 · unidbg/Qiling 动态定值

> 逆向分析经验 · 第 2 篇「so 分析」
> 场景：不依赖真机，把 Android `.so` 拉回 Windows 本地做 **静态分析 + 动态执行（unidbg / Qiling）**。
> 案例：某短视频 App 网络层 so（arm64，7MB，带 JNI 回调）。
> 一句话：**静态定面（位置 / 接口 / 特征），动态定值（密钥 / 变换结果 / 行为）** —— 先静态约能定 80% 的结构信息，剩下 20% 靠跑。

## 目录
- [一、调用图](#一调用图)
- [二、总览：目标 / 决策表](#二总览目标--决策表)
- [三、静态技术链（5 分钟定面）](#三静态技术链5-分钟定面)
- [四、黑盒转白盒](#四黑盒转白盒捕获接口--枚举字符串--直接调函数)
- [五、分层判据：谁读环境，就在哪层 hook](#五分层判据谁读环境就在哪层-hook)
- [六、本地动态执行（unidbg / Qiling）](#六本地动态执行unidbg--qiling)
- [七、案例闭环](#七案例闭环)
- [八、踩坑清单](#八踩坑清单)
- [九、速查](#九速查)
- [附录：工程文件](#附录工程文件)

---

# 一、调用图

## 1. 工作流

```
拿到 .so
  |
  +-- 1. 明确目标: 要测的六件事(接口/材料/明文/绕过/依赖/检测)
  |
  +-- 2. 静态定面 (file/readelf/strings/capstone/IDA)
  |      +-- readelf -h/-S/-l/-d/-r  -> 架构/壳/布局
  |      +-- readelf --dyn-syms + strings -> 接缝/特征串
  |      +-- capstone/IDA 反汇编 -> init_array / JNI_OnLoad / 目标函数
  |
  +-- 3. [需跑] 本地动态执行 (选一)
  |      +-- unidbg  -> 带 JNI / Java 回调的场景首选
  |      +-- Qiling  -> 自包含算法 / 无 JNI / 需补重定位
  |
  +-- 4. [需真机] 设备端 Frida hook
  |
  +-- 5. 产出: 锚点清单 / 材料 / 明文 / 绕过 / 依赖清单
```

## 2. 分层判据图（谁读环境 → 就在哪层 hook）

```
目标"读环境"的方式
  |
  +-- Java API (getPackageName / Settings.Secure)  -> Java 层   -> 改方法返回       [Frida Java.use]
  +-- libc 函数 (open/prctl/popen)                 -> libc 层   -> attach libc导出   [Frida]
  +-- libc syscall() 包装器                        -> libc 层   -> hook syscall      [Frida]
  +-- 内联 svc #0                                  -> raw svc   -> ❌ libc 钩不到    -> patch svc / Stalker
  +-- 自带 syscall 引擎 (xxx_syscall(nr,...))      -> raw svc   -> hook 那个引擎     [Frida]
  +-- 100 取串函数 / VMP                           -> 代码级    -> 反编译 + 枚举     [IDA + unidbg]
```
判据：`objdump`/脚本扫 `.text` 数**内联 svc 条数**（0=全 libc；>0=有绕过）。

## 3. 黑盒转白盒

```
库静态读不动 (混淆/VMP/串混淆)
  |
  +-- 导出少、逻辑在 JNI_OnLoad/init_array --> 跑 init 看它调什么
  +-- Java 侧 native 不明 -----------------> hook RegisterNatives --> 全部 native 名+签名+fnPtr
  +-- 串"加密/乱码" -----------------------> 找取串函数 + 枚举 id --> 完整字符串表
  +-- 有分发/协议函数 ---------------------> callFunction 喂参 --> 命令语义/协议格式
  +-- 库早崩/卡住 -------------------------> auto-map 未映射页 + 补 JNI --> init 跑到底
```

## 4. 选型

```
纯算法(白盒/自实现加密)  --> Qiling (补环境后跑)
带 JNI + Java 回调       --> unidbg (MyJni 演 Java)
需真实网络/系统调用      --> 真机 Frida
反复调参、秒级重试       --> unidbg / Qiling 本地
```

---

# 二、总览：目标 / 决策表

**核心原则**：
1. **静态先行**：`readelf`/`strings`/反汇编能定结构信息，别一上来就跑。
2. **导出与接缝 = 逻辑面清单**：先把入口（JNI / 导出 / 注册表）列全，再逐个攻。
3. **材料不在代码里就别硬逆算法**：先定位运行时来源（资源/文件/网络/派生），再决定喂数据 or 抄参数。
4. **hook 最小化**：只顶掉必须顶的，其余让库自己跑，减少行为偏差。
5. **闭环验证**：**变换 A 的结果能被逆向变换 B 还原** = 环境/参数补对了。
6. **先定目标再动手**。

| 场景 | 首选工具 |
| --- | --- |
| 纯算法（白盒 / 自实现加密） | Qiling（补环境后跑） |
| 带 JNI + Java 回调 | **unidbg（MyJni 演 Java）** |
| 需要真实网络 / 系统调用 | 真机 Frida |
| 反复调参、秒级重试 | unidbg / Qiling 本地 |

---

# 三、静态技术链（5 分钟定面）

## 3.1 架构 / 壳 / 布局
```bash
file target.so
readelf -h target.so        # ELFCLASS: 32=armv7 / 64=arm64 ; e_machine=AArch64
readelf -S target.so        # 节表: .text/.dynsym/.init_array/.data/.rodata
readelf -l target.so        # 程序头: LOAD R+X=代码 / RW=GOT
readelf -d target.so | grep INIT_ARRAY   # 启动函数表(比 JNI_OnLoad 更早)
```
| 节名 | 作用 | 壳特征 |
| --- | --- | --- |
| `.text` | 代码 | 干净 so 必有 |
| `.dynsym`/`.dynstr` | 导出符号 | 被抹 = stripped + 壳 |
| `.init_array` | 启动函数表 | 壳解密/反调试/环境校验常藏 |
| `.rodata` | 字符串/常量 | `strings` 首选 |

**无偏移 so**：`p_offset == p_vaddr` 时文件偏移=虚址，可直读；否则 `file_off = vaddr - seg.vaddr + seg.offset`（务必先转换）。GOT 槽查 `readelf -r`。

## 3.2 接缝（最重要）
```bash
readelf --dyn-syms target.so | grep Java_     # JNI 命名: Java_包_类_方法 (转义 _1=_ / _2=; / _3=[)
readelf --dyn-syms target.so                  # 全部导出(除 JNI, 导出 C 函数也是接缝)
```
判据：能把"对外接口清单"列全 → 知道 hook 哪些点。

## 3.3 特征串
```bash
strings -a target.so | grep -iE "key|salt|cipher|aes|gcm|sm4|frida|assets|/proc/|ptrace"
```

## 3.4 反汇编
```python
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM); md.detail = True
for i in md.disasm(data[addr:addr+length], addr):
    print(f"{i.address:#x}: {i.mnemonic} {i.op_str}")
```
- 函数序言 `STP x29,x30`；查表（白盒）连续 `ldr [x_base,#off]`；取串 `adrp+add/ldr`。
- 大 SO **先定范围再反汇编**，别全量 objdump（会爆炸）。

## 3.5 静态 → 动态 决策
| 问题 | 静态可答? |
| --- | --- |
| 函数在哪、叫什么 | ✅ readelf + 反汇编 |
| 调了哪些外部 API | ✅ `bl` + 导入表 |
| 输入→输出是什么变换 | ❌ 需运行（白盒/加密） |
| 密钥/盐值到底是什么 | ❌ 运行时才产生 |

---

# 四、黑盒转白盒：捕获接口 · 枚举字符串 · 直接调函数

> 库**静态读不动**（混淆/VMP/串混淆）时，用 unidbg/Qiling 在本地把"接口·字符串·函数"抠出来。

| 信号 | 招式 | 拿到 |
| --- | --- | --- |
| 导出少、逻辑在 `JNI_OnLoad`/`init_array` | 跑 init，看它调什么 | 初始化行为/依赖 |
| Java 侧 native 方法不明 | **hook `RegisterNatives`** | 全部 native 名+签名+fnPtr |
| 串"加密/乱码" | 找**取串函数**并枚举 | 完整字符串表 |
| 有"分发/协议"函数 | `callFunction` 逐个喂参数 | 命令语义/协议格式 |
| 库"早崩/卡住" | **auto-map 未映射页** + 补 JNI | 让 init 跑到底 |
| 想知道"哪层读环境" | 分层判据（见§五） | hook 落点 |

## 4.1 捕获接口：hook `RegisterNatives`
- 库在 `JNI_OnLoad` 里 `env->RegisterNatives(clazz, methods[], n)`。
- `RegisterNatives` 是 **JNIEnv 函数表第 215 项**。
- 做法：造假 JNIEnv（函数表全指向 `ret` 桩），**第 215 槽**指向自己的桩 → 读参 `(env,clazz,methods,n)`。
- `JNINativeMethod = { const char* name; const char* sig; void* fnPtr; }`（24B/项）。
- **产出**：全部 native 方法名+签名+**fnPtr（=base+offset）** → 后续逐个 `callFunction` 跑。

```java
// 伪: 第 215 槽 -> 桩, 桩里读 methods+i*24 的 name/sig/fnPtr
for (int i = 0; i < n; i++) {
    Pointer m = methods.add(i * 24);
    log("name=" + m.getPointer(0).getString(0) + " sig=" + m.getPointer(8).getString(0)
        + " fn=0x" + Long.toHexString(m.getPointer(16).address - module.base));
}
```

## 4.2 枚举字符串：找"取串函数"再枚举 id
- 判据：反编译出现 `xxx(id)` → `array[id % N]()` 这种"**按 id 取串**" = **N 个取串函数的串混淆**（不是真加密）。
- 用 IDA 拿到取串函数偏移与 `id%N` 的 N → **`callFunction(取串函数, id)` 枚举**读返回 C 串。

```java
for (long id = 0; id < N_upper; id++) {
    Number r = module.callFunction(emulator, <取串函数offset>, id);   // offset 相对 base
    System.out.println("[" + id + "] '" + readCStr(((Emulator<?,?>)emulator), r.longValue()) + "'");
}
```

## 4.3 直接调任意函数：`Module.callFunction`
```java
Number callFunction(Emulator<?,?> emulator, long offset, Object... args);
```
- **坑**：`offset` **相对模块基址**；返回值是 `Number`（**不是数组**，当 `Number[]` 用会编译错）。

---

# 五、分层判据：谁读环境，就在哪层 hook

| 读环境方式 | 所在层 | hook 落点 | 工具 |
| --- | --- | --- | --- |
| Java API（`getPackageName`/`Settings.Secure`） | Java | 改方法返回 | Frida `Java.use` |
| **libc 函数**（`open`/`prctl`/`popen`） | libc | `Interceptor.attach(libc导出)` | Frida |
| **libc `syscall()` 包装器** | libc | hook `syscall` | Frida |
| **内联 `svc #0`** | raw svc | **libc 钩不到** → patch svc / Stalker | `frida_svc_patch` |
| **自带 syscall 引擎** | raw svc | **hook 那个引擎** | Frida |
| **100 取串函数 / VMP** | 代码级 | 反编译 + 枚举 | IDA + unidbg |

---

# 六、本地动态执行（unidbg / Qiling）

## 6.1 选型（互补）
| | Qiling | unidbg |
| --- | --- | --- |
| 层 | 纯原生 | 原生 + 真 Dalvik/JNI |
| 强项 | 干净 hook / 追 syscall | **真 JNIEnv**：能调 native 方法、返回 Java 对象 |
| 用途 | 看"读环境行为"（文件/syscall） | **枚举字符串、跑接口、触发自退** |
| 局限 | JNIEnv 全 stub | hook 地址/API 要试 |

**组合拳**：Qiling 看**行为**（读了哪些 `/proc`），unidbg 做**提取**（枚举串、调函数）。

## 6.2 让库"跑到底"：auto-map 未映射页
- 库 init 常因缺环境**早崩**（`UC_ERR_FETCH/WRITE_UNMAPPED`）。
- **Qiling**：`ql.uc.hook_add(UC_HOOK_MEM_UNMAPPED, cb)`，cb 里 `mem_map(addr & ~0xfff, 0x1000)` 返回 True → 继续跑。
- 效果：`JNI_OnLoad` 从"早崩"到"**跑到底**"，触发真正行为（读文件、进 syscall 引擎）。

## 6.3 unidbg 要点
1. **后端用 Unicorn2**（`new Unicorn2Factory(true)`）—— **Dynarmic 的 `hook_add_new(CodeHook)` 抛 `UnsupportedOperationException`**。
2. **补环境(桩)**：库缺 Java 方法抛 `UnsupportedOperationException` → `AbstractJni` 子类 override 补。
3. **hook 最小化**：只顶资源/文件读取等必须的，其余让库自己跑（减少偏差）。
4. `CodeHook` 接口 = `hook(Backend,long,int,Object)` + `Detachable{onAttach(UnHook),detach()}`。
5. maven 根 pom 常设 `maven.test.skip=true` → 须 `-Dmaven.test.skip=false`；`install` 须 `-Dgpg.skip=true`。

---

# 七、案例闭环

## 7.1 网络层 so（Cronet 类）
```
① 静态: readelf 定架构; strings|grep 找特征串; IDA 按字符串 xref 定位函数
         (证书校验入口 / 公钥固定 / KProxy 重写)
② 动态(unidbg): 加载 so + JNI_OnLoad + 调 native 拿真值
         -> nativeGetVersionString() = "4.50.1"
③ 验证: 真机 Frida 直调同名方法 = "4.50.1"  -> 拟真可信 ✅
```
- 关键：**native 的证书校验入口是 JNI 桥，反调 Java**（`verifyServerCertificates`）→ 校验其实在 Java，可 hook。
- 静态 xref 找到的"重写/固定"函数（native）用 `callFunction`/hook 观察。

## 7.2 取串/接口（串混淆类）
```
串混淆: 反编译见 xxx(id)->array[id%N]()  --IDA拿偏移--> callFunction 枚举 -> 全字符串表
接口:   hook RegisterNatives             --unidbg----> native 名+签名+偏移清单
```

## 7.3 产物闭环
```
RegisterNatives -> 接口清单(native 方法)
取串函数枚举    -> 字符串表(检测路径/命令/协议)
callFunction    -> 命令语义/协议格式/加解密 I/O
分层判据        -> hook 落点(Java/libc/svc/引擎)
=> 黑盒变白盒; 再据此写 Frida 或补环境。
```

---

# 八、踩坑清单

| 坑 | 现象 | 对策 |
| --- | --- | --- |
| 32/64 位搞错 | 反汇编乱码 | 先 `readelf -h` 看 `ELFCLASS` |
| 无偏移假设 | `data[addr]` 读错 | 只有 `p_offset==p_vaddr` 能直读，否则先转换 |
| 函数长度靠猜 | 反汇编溢出到邻函数 | 用相邻符号地址差 / `st_size` |
| `strings` 看漏 | 漏关键字符串 | 用 `strings -a`（含全段） |
| 白盒表当普通代码 | 看不懂 `ldr` 轮转 | 别硬看，转动态/模拟 |
| 强混淆死磕 | 时间黑洞 | 定位外部资产 / 转运行时观察 |
| `callFunction` 返回当数组 | 编译错 | 返回是 `Number`，`offset` 相对 base |
| Dynarmic code hook | `UnsupportedOperationException` | 换 **Unicorn2** 后端 |
| 库早崩 | `UC_ERR_*_UNMAPPED` | auto-map 未映射页 + 补 JNI |
| 补环境过度 | 行为偏差/结果错 | **hook 最小化**，其余让库自己跑 |

---

# 九、速查

```sh
# 5 分钟静态确认
file target.so
readelf -h -S -l -d -r target.so
readelf --dyn-syms target.so | grep Java_
strings -a target.so | grep -iE "key|salt|cipher|aes|gcm|sm4|frida|assets|/proc/"
# 数内联 svc (判是否绕过 libc)
objdump -d target.so | grep -c "svc"
# unidbg 跑
mvnw -o -pl unidbg-android -Dgpg.skip=true -Dmaven.test.skip=false test-compile exec:java \
     -Dexec.mainClass=... -Dexec.classpathScope=test
```

---

# 附录：工程文件

> 可运行文件见 [`code/`](code/) 目录；下面为对应源码。

## A1. so_5min.sh —— 5 分钟静态定面
```sh
#!/bin/sh
# 用法: sh so_5min.sh target.so
T=${1:?so}
echo "== file =="; file "$T"
echo "== header =="; readelf -h "$T" | grep -E "Class|Machine"
echo "== sections =="; readelf -S "$T" | grep -E "text|dynsym|init_array|rodata"
echo "== dynsym(Java) =="; readelf --dyn-syms "$T" | grep Java_ | head -40
echo "== init_array =="; readelf -d "$T" | grep INIT_ARRAY
echo "== strings =="; strings -a "$T" | grep -iE "key|salt|cipher|aes|gcm|sm4|frida|assets|/proc/|ptrace" | head -40
echo "== inline svc count =="; objdump -d "$T" 2>/dev/null | grep -c "svc"
```

## A2. disasm_arm64.py —— capstone 定点反汇编
```python
# 用法: python disasm_arm64.py target.so <hex_offset> <hex_len>
import sys, capstone
path, off, ln = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
data = open(path, 'rb').read()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM); md.detail = True
for i in md.disasm(data[off:off+ln], off):
    print(f"{i.address:#x}: {i.mnemonic} {i.op_str}")
```

## A3. unidbg 取串枚举（串混淆）
```java
// 反编译见 xxx(id)->array[id%N]() 时, 用 callFunction 枚举 id
private static String readCStr(Emulator<?, ?> emu, long addr) {
    return emu.getMemory().pointer(addr).getString(0);
}
// 注意: offset 相对模块基址; 返回 Number 不是数组
for (long id = 0; id < N_UPPER; id++) {
    Number r = module.callFunction(emulator, OFFSET_TAKE_STRING, id);
    System.out.println("[" + id + "] '" + readCStr(emulator, r.longValue()) + "'");
}
```

## A4. RegisterNatives 捕获（伪）
```java
// JNINativeMethod = {name, sig, fnPtr} 24B/项; RegisterNatives = JNIEnv 表第 215 项
// 造假 JNIEnv: 函数表全指 ret 桩, 第 215 槽 -> 本桩
void onRegisterNatives(long clazz, long methods, int n) {
    for (int i = 0; i < n; i++) {
        Pointer m = memory.pointer(methods + i * 24L);
        String name = m.getPointer(0).getString(0);
        String sig  = m.getPointer(8).getString(0);
        long   fn   = m.getPointer(16).address - module.base;   // 相对偏移
        System.out.println(name + " " + sig + " @0x" + Long.toHexString(fn));
    }
}
```

## A5. Qiling auto-map 未映射页（让库跑到底）
```python
# 库 init 早崩 (UC_ERR_FETCH/WRITE_UNMAPPED) 时, 自动映射继续跑
def hook_unmapped(uc, access, address, size, value, user_data):
    page = address & ~0xfff
    uc.mem_map(page, 0x1000)
    return True
ql.uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)
ql.run()
```

---

# 工程文件

> 本仓库 [`code/`](code/) 目录下的可复用脚本：

| 文件 | 说明 |
| --- | --- |
| [`code/so_5min.sh`](code/so_5min.sh) | 5 分钟静态定面（file / readelf / strings / svc 计数） |
| [`code/disasm_arm64.py`](code/disasm_arm64.py) | capstone 定点反汇编 |
| [`code/unidbg_take_string.java`](code/unidbg_take_string.java) | 串混淆：枚举取串函数 id → dump 全字符串表 |
| [`code/register_natives.js`](code/register_natives.js) | 捕获接口：hook RegisterNatives → native 方法清单 |
| [`code/qiling_automap.py`](code/qiling_automap.py) | auto-map 未映射页 → 让库跑到底 |

---

**仓库**：https://github.com/Machao147258-max/-fenxijiyantop1-so
