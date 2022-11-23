package com.zhangyue.iReader.JNI.util;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
public class JNISecurity extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Memory memory;
    private final Module module;
    private final DvmClass JNISecurity;

    static String apk_path;



    JNISecurity() {
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName("com.chaozh.iReaderFree").addBackendFactory(new Unicorn2Factory(true)).build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(false);
        memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File(apk_path));
        vm.setJni(this);
        vm.setVerbose(false);
        new JniGraphics(emulator,vm).register(memory);
        new AndroidModule(emulator,vm).register(memory);
        JNISecurity = vm.resolveClass("com/zhangyue/iReader/JNI/util/JNISecurity");
        DalvikModule dm = vm.loadLibrary("tingReader" ,false);
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);
    }


    String javaSign(String str) throws Exception{
        ByteArray ret = JNISecurity.callStaticJniMethodObject(emulator,
                "hash(Ljava/security/Signature;Ljava/security/KeyFactory;[B)[B",
                ProxyDvmObject.createObject(vm, Signature.getInstance("SHA1WithRSA")),
                ProxyDvmObject.createObject(vm,  KeyFactory.getInstance("RSA")),
                str.getBytes("utf-8"));
        byte[] result = (byte[]) ret.getValue();
        return new String(Base64.getEncoder().encode(result));
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature){
            case "java/security/spec/PKCS8EncodedKeySpec-><init>([B)V":
                byte[] key = (byte[]) vaList.getObjectArg(0).getValue();
                PKCS8EncodedKeySpec pkcseEncodedkeyspec = new PKCS8EncodedKeySpec(key);
                return dvmClass.newObject(pkcseEncodedkeyspec);
        }
        return super.newObjectV(vm, dvmClass, signature, vaList);
    }



    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature){
            case "com/zhangyue/iReader/app/APP->mAppContext:Landroid/content/Context;":
                return vm.resolveClass("android/content/Context").newObject(null);
        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature){
            case "android/content/Context->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
                return vm.resolveClass("android/content/pm/ApplicationInfo").newObject(signature);
            case "java/security/KeyFactory->generatePrivate(Ljava/security/spec/KeySpec;)Ljava/security/PrivateKey;":
                KeyFactory factory = (KeyFactory) dvmObject.getValue();
                DvmObject<?> spec = vaList.getObjectArg(0);
                KeySpec keyspec = (KeySpec) spec.getValue();
                try{
                    return vm.resolveClass("java/security/PrivateKey").newObject(factory.generatePrivate(keyspec));
                }catch (java.security.spec.InvalidKeySpecException exception){
                    return null;
                }
            case "java/security/Signature->sign()[B":
                Signature signature1 = (Signature) dvmObject.getValue();
                try {
                    return new ByteArray(vm,signature1.sign());
                } catch (java.security.SignatureException exception){
                    return null;
                }

        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature){
            case "java/security/Signature->initSign(Ljava/security/PrivateKey;)V":
                Signature signature1 = (Signature) dvmObject.getValue();
                DvmObject<?> spec = vaList.getObjectArg(0);
                PrivateKey privatekey = (PrivateKey) spec.getValue();
                try{
                    signature1.initSign(privatekey);
                    return;
                } catch (java.security.InvalidKeyException exception){
                    return;
                }
            case "java/security/Signature->update([B)V":
                Signature signature2 = (Signature) dvmObject.getValue();
                ByteArray data = (ByteArray)  vaList.getObjectArg(0);;
                try{
                    signature2.update(data.getValue());
                }catch (java.security.SignatureException exception){}
                return;
        }
        super.callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        switch (signature){
            case "android/content/pm/ApplicationInfo->packageName:Ljava/lang/String;":
                return new StringObject(vm,"com.chaozh.iReaderFree");
        }
        return super.getObjectField(vm, dvmObject, signature);
    }

    public static String makeAes() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return new String(Base64.getEncoder().encode(keyGenerator.generateKey().getEncoded()));
    }

    public static String makeAesKey(String aes) throws Exception {
        String key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCAqSnnZ9BVOZjIMTkATIn29nM0hLOsQsXlPbqrGE4CUmDCncVBHdkfEIF73tSKjhYfLuPH1gDtHRKeCC1DQ4uYJL83oeHtXSldGUlfuv9rh0Q/2Hxl3iG8TUc1drTKTZFfkQWWseTb3vAx8Ggse9xZNTjI6enOEjNyGlAIF+RKrwIDAQAB";
        PublicKey e10 = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(key)));
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(1, e10);
        return new String(Base64.getEncoder().encode(cipher.doFinal(aes.getBytes("UTF-8"))));
    }

    public static String makePassword(String str, String str2) throws Exception {
        byte[] bytes = str.getBytes("UTF-8");
        byte[] encoded = new SecretKeySpec(Base64.getDecoder().decode(str2), "AES").getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(encoded, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(encoded);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(1, secretKeySpec, ivParameterSpec);
        return new String(Base64.getEncoder().encode(cipher.doFinal(bytes)));
    }

    public static final String getSortedParamStr(Map<String, String> map) {
        StringBuilder sb2 = new StringBuilder();
        ArrayList arrayList = new ArrayList();
        for (String str : map.keySet()) {
            arrayList.add(str);
        }
        Collections.sort(arrayList);
        int size = arrayList.size();
        for (int i10 = 0; i10 < size; i10++) {
            String str2 = (String) arrayList.get(i10);
            String str3 = map.get(str2);
            sb2.append("&");
            sb2.append(str2);
            sb2.append("=");
            sb2.append(str3);
        }
        return sb2.toString().substring(1);
    }

    public static final void login(String username,String password) throws Exception {
        JNISecurity sign = new JNISecurity();
        String aes = makeAes();
        String aes_key = makeAesKey(aes);
        HashMap<String,String> arrayMap = new HashMap<String,String>();
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("AesKey", aes_key);
        JSONObject jSONObject2 = new JSONObject();
        jSONObject2.put("password", password);
        jSONObject.put("Data", makePassword(jSONObject2.toString(), aes));
        arrayMap.put("data", jSONObject.toString());
        arrayMap.put("user_name", username);
        arrayMap.put("imei", "__39827dd5eb14217a");
        arrayMap.put("ver", "1.0");
        arrayMap.put("channel_id", "108045");
        arrayMap.put("version_id", "17490003");
        arrayMap.put("device", "Pixel 2");
        arrayMap.put("is_mergeme", "1");
        arrayMap.put("encrypt_method", "1");
        arrayMap.put("timestamp", String.valueOf(System.currentTimeMillis()));
        String data = getSortedParamStr(arrayMap);
        String result = sign.javaSign(data);
        System.out.println(arrayMap.get("data").toString());
        System.out.println(arrayMap.get("timestamp").toString());
        System.out.println(result);
    }

    public static final void sign(String data) throws Exception {
        JNISecurity sign = new JNISecurity();
        String result = sign.javaSign(data);
        System.out.println(result);
    }


    public static void main(String[] args) throws Exception {
        apk_path = args[1];
        switch (args[0]){
            case "login":
                login(args[2],args[3]);
                break;
            case "sign":
                sign(args[2]);
                break;
            default:
                break;
        }
    }
}
