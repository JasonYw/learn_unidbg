package a;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;

import javax.crypto.Cipher;
import java.io.File;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class d extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Memory memory;
    private final Module module;
    static String apk_path;

    d(){
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName("com.qidian.QDReader").addBackendFactory(new Unicorn2Factory(true)).build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(false);
        memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(19));
        vm = emulator.createDalvikVM(new File(apk_path));
        vm.setJni(this);
        vm.setVerbose(false);
        new JniGraphics(emulator,vm).register(memory);
        new AndroidModule(emulator,vm).register(memory);
        DalvikModule dm = vm.loadLibrary("d-lib" ,false);
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);
    }

    void callC() {
        DvmClass clz = vm.resolveClass("a/d");
        String testarg = "1275e5e062ee0b356183c66b10001af16b03|1275e5e062ee0b356183c66b10001af16b03|" + System.currentTimeMillis()/1000;
        ByteArray res = clz.callStaticJniMethodObject(
                emulator,
                "c(Ljava/lang/String;)[B",
                testarg
        );
        System.out.println(new String(Base64.getEncoder().encode(res.getValue())));
    }


    public static void callRsaEncrypt(String str) throws Exception {
        String plainPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+ca+tWW42rQyjC4r4iefGj+vNpZWe4frxl/u1CBYxjCwMT1E+v6PxEPf0CKya7o7SfAcNsKhiN6YIRYMXnEvvRsZRlrvA0UicWZMCLBAMI6TnCz2vlKfjolORmp112j4iOCH6S+v/UomGuMvyW1KuOM0ttpEDkW/NiKNke0rJQQIDAQAB";
        RSAPublicKey publicKey =  (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(plainPublicKey)));
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(1, publicKey);
        byte[] doFinal = cipher.doFinal(str.getBytes());
        String encodeToString = Base64.getEncoder().encodeToString(doFinal);
        System.out.println(encodeToString);
    }




    public static void main(String[] args) throws Exception{
        apk_path = "C:\\Users\\rico\\Desktop\\apk\\com.qidian.QDReader.apk";
        d test = new d();
        test.callC();
        callRsaEncrypt("a0123456789");
    }


}
