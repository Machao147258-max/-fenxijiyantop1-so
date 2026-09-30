// register_natives.js —— 捕获接口: hook RegisterNatives, dump 全部 native 方法名+签名+fnPtr
// RegisterNatives 是 JNIEnv 函数表第 215 项; JNINativeMethod = {name, sig, fnPtr} 24 字节/项
// 思路: 拦 JNI_OnLoad 拿 env -> patch env 表第 215 槽 -> 读 (clazz, methods[], n)
// 注意: 转译(Houdini)环境下 native hook 不触发; 本脚本用于能跑 native 的 so / x86_64 场景

var TARGET = 'libtarget.so';           // 改成你的 so
var SLOT_REGISTER_NATIVES = 215;       // JNIEnv 表索引

var onLoad = Module.findGlobalExportByName ? null : null;
// Frida 17: 用模块实例拿导出
var JNI_OnLoad = null;
try { JNI_OnLoad = Process.getModuleByName(TARGET).getExportByName('JNI_OnLoad'); } catch (e) {}
if (!JNI_OnLoad) JNI_OnLoad = Module.findExportByName(TARGET, 'JNI_OnLoad');
if (!JNI_OnLoad) { console.log('[-] no JNI_OnLoad in ' + TARGET); }

var patched = false;
Interceptor.attach(JNI_OnLoad, {
  onEnter: function (args) {
    this.env = args[0];
  },
  onLeave: function (ret) {
    if (patched) return;
    patched = true;
    var env = this.env;
    var table = env.readPointer();                          // JNINativeInterface*
    var slot = table.add(SLOT_REGISTER_NATIVES * Process.pointerSize);
    var orig = slot.readPointer();
    Interceptor.attach(orig, {
      onEnter: function (a) {
        var clazz = a[1], methods = a[2], n = a[3].toInt32();
        try { console.log('[RegisterNatives] clazz=' + clazz + ' n=' + n); } catch (e) {}
        for (var i = 0; i < n; i++) {
          var m = methods.add(i * 24);                      // {name, sig, fnPtr}
          try {
            var name = m.readPointer().readCString();
            var sig = m.add(8).readPointer().readCString();
            var fn = m.add(16).readPointer();
            console.log('  ' + name + ' ' + sig + ' @' + fn);
          } catch (e) { console.log('  [?] ' + e); }
        }
      }
    });
    console.log('[+] RegisterNatives (slot ' + SLOT_REGISTER_NATIVES + ') hooked');
  }
});
