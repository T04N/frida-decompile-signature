import Java from "frida-java-bridge";
import { log } from "./logger.js";

const header = Memory.alloc(16);
header
    .writeU32(0xdeadbeef).add(4)
    .writeU32(0xd00ff00d).add(4)
    .writeU64(uint64("0x1122334455667788"));
log(hexdump(header.readByteArray(16) as ArrayBuffer, { ansi: true }));

// For Android, use libc instead of libSystem.B.dylib
try {
    Process.getModuleByName("libc.so")
        .enumerateExports()
        .slice(0, 16)
        .forEach((exp, index) => {
            log(`export ${index}: ${exp.name}`);
        });
} catch (e) {
    log(`Error enumerating libc.so exports: ${e}`);
}

Interceptor.attach(Module.getGlobalExportByName("open"), {
    onEnter(args) {
        const path = args[0].readUtf8String();
        log(`open() path="${path}"`);
    }
});

if (Java.available) {
    Java.perform(() => {
        send({
            type: "status",
            message: "Application class-loader now available"
        });

        // Hook Signature.toByteArray() to capture app signatures
        try {
            var Sig = Java.use("android.content.pm.Signature");
            var Base64 = Java.use("android.util.Base64");
            
            Sig.toByteArray.implementation = function(){
                var b = this.toByteArray();
                try {
                    var b64 = Base64.encodeToString(b, 0);
                    var hex = Array.prototype.map.call(b, function(x){ 
                        return ('0'+(x&0xff).toString(16)).slice(-2)
                    }).join('').toUpperCase();
                    send("[SIGN-BYTES] base64=" + b64 + " hex=" + hex);
                } catch(e){
                    send("[SIGN-BYTES-ERR] " + e);
                }
                return b;
            };
            send("[OK] Hooked Signature.toByteArray()");
        } catch (e) {
            send("[ERROR] Failed to hook Signature: " + e);
        }

        // Hook MessageDigest to capture SHA-256 hash of signature
        try {
            var MessageDigest = Java.use("java.security.MessageDigest");
            var Base64 = Java.use("android.util.Base64");
            
            // Hook MessageDigest.getInstance
            MessageDigest.getInstance.overload("java.lang.String").implementation = function(algorithm: string) {
                var result = this.getInstance(algorithm);
                if (algorithm === "SHA-256") {
                    send("[SHA256] MessageDigest.getInstance called for SHA-256");
                    
                    // Hook digest method
                    result.digest.overload().implementation = function() {
                        var hashBytes = this.digest();
                        var hashBase64 = Base64.encodeToString(hashBytes, 0);
                        send("[SHA256-HASH] Final SHA-256 hash: " + hashBase64);
                        return hashBytes;
                    };
                }
                return result;
            };
            
            // Also hook update method to see what data is being hashed
            MessageDigest.update.overload("[B").implementation = function(input: any) {
                var result = this.update(input);
                send("[SHA256] MessageDigest.update called with " + input.length + " bytes");
                return result;
            };
            
            send("[OK] Hooked MessageDigest for SHA-256 capture");
        } catch (e) {
            send("[ERROR] Failed to hook MessageDigest: " + e);
        }

        // Hook Cipher.doFinal() to capture AES encryption result instead of method f()
        // This approach is safer and avoids potential crashes
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var Base64 = Java.use("android.util.Base64");
            
            // Hook Cipher.doFinal to capture encrypted data
            Cipher.doFinal.overload("[B").implementation = function(input: any) {
                var result = this.doFinal(input);
                var resultBase64 = Base64.encodeToString(result, 0);
                send("[AES-ENCRYPT] Cipher.doFinal() called");
                send("[AES-ENCRYPT] Input length: " + input.length + " bytes");
                send("[AES-ENCRYPT] Encrypted result (Base64): " + resultBase64);
                return result;
            };
            
            // Also hook Cipher.getInstance to see what algorithm is being used
            Cipher.getInstance.overload("java.lang.String").implementation = function(transformation: string) {
                var result = this.getInstance(transformation);
                if (transformation.indexOf("AES") !== -1) {
                    send("[AES-ENCRYPT] Cipher.getInstance called with: " + transformation);
                }
                return result;
            };
            
            send("[OK] Hooked Cipher.doFinal() for AES encryption capture");
        } catch (e) {
            send("[ERROR] Failed to hook Cipher: " + e);
        }
    });
} else {
    console.log("No Java VM in this process");
}
