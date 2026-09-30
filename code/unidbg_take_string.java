// unidbg_take_string.java —— 串混淆: 枚举"取串函数"的 id, dump 全字符串表
// 判据: 反编译里出现 xxx(id) -> array[id % N]() 这种"按 id 取串" = N 个取串函数的串混淆
// 注意: callFunction 的 offset 相对模块基址; 返回值是 Number(不是数组)
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import java.io.File;

public class unidbg_take_string extends AbstractJni {

    private static final String SO = "libtarget.so";     // 改成你的 so
    private static final long TAKE_STRING = 0x1234L;      // 取串函数偏移(IDA 里拿, 相对 base)
    private static final long ID_UPPER = 20000L;          // id 枚举上限

    public static void main(String[] args) throws Exception {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.example.app")
                .addBackendFactory(new Unicorn2Factory(true))       // 必须 Unicorn2
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        VM vm = emulator.createDalvikVM();
        vm.setJni(new unidbg_take_string());
        vm.setVerbose(false);

        Module module = vm.loadLibrary(new File(SO), true).getModule();
        System.out.println("base=0x" + Long.toHexString(module.base));

        for (long id = 0; id < ID_UPPER; id++) {
            try {
                Number r = module.callFunction(emulator, TAKE_STRING, id);
                long p = r.longValue();
                if (p == 0) continue;
                String s = emulator.getMemory().pointer(p).getString(0);
                System.out.println("[" + id + "] '" + s + "'");
            } catch (Throwable t) {
                // 越界/异常 id 直接跳过
            }
        }
        emulator.close();
    }
}
