package com.km.encryption.api;


import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.AssetManager;
import com.github.unidbg.linux.android.dvm.api.ClassLoader;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;
import java.io.File;
import java.nio.charset.StandardCharsets;

public class Security extends AbstractJni {

    private final AndroidEmulator emulator;
    private final Memory memory;
    private final VM vm;
    static  String apk_path;
    private final Module module;

    Security(){
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName("com.kmxs.reader").addBackendFactory(new Unicorn2Factory(true)).build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(false);
        memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File(apk_path));
        vm.setJni(this);
        vm.setVerbose(false);
        new JniGraphics(emulator,vm).register(memory);
        new AndroidModule(emulator,vm).register(memory);
        DalvikModule dm = vm.loadLibrary("common-encryption",false);
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);
    }

    void callSign(String arg_) {
        DvmClass clz = vm.resolveClass("com/km/encryption/api/Security");
        StringObject ret = clz.callStaticJniMethodObject(emulator, "sign([B)Ljava/lang/String;", new ByteArray(vm, arg_.getBytes(StandardCharsets.UTF_8)));
        System.out.println(ret.getValue());
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature){
            case "java/lang/Class->getClassLoader()Ljava/lang/ClassLoader;":
                return new ClassLoader(vm, signature);
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }


    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature){
            case "com/km/encryption/generator/KeyGenerator->getKey()Ljava/lang/String;":
                return new StringObject(vm,"8w1");
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature){
            case "com/km/encryption/generator/KeyGenerator->assetManager:Landroid/content/res/AssetManager;":
                return new AssetManager(vm, signature);
        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    public static void main(String[] args) {
        apk_path = args[0];
        Security test = new Security();
        test.callSign(args[1]);
    }
}
