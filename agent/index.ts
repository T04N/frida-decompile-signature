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
        // Helper: remove newlines/whitespace from Base64 for URL safety
        const sanitizeBase64ForUrl = (s: string): string => {
            if (!s) return s;
            return s
                .replace(/\s+/g, "")
                .replace(/\+/g, "-")       // '+' -> '-'
                .replace(/\//g, "_")       // '/' -> '_'
                .replace(/=+$/g, "");       // strip trailing '=' padding
        };
        send({
            type: "status",
            message: "Application class-loader now available"
        });

        // Hook Signature.toByteArray() to capture app signatures - DISABLED to prevent crash
        // try {
        //     var Sig = Java.use("android.content.pm.Signature");
        //     var Base64 = Java.use("android.util.Base64");
        //     
        //     Sig.toByteArray.implementation = function(){
        //         var b = this.toByteArray();
        //         try {
        //             var b64 = Base64.encodeToString(b, 0);
        //             var hex = Array.prototype.map.call(b, function(x){ 
        //                 return ('0'+(x&0xff).toString(16)).slice(-2)
        //             }).join('').toUpperCase();
        //             // send("[SIGN-BYTES] base64=" + b64 + " hex=" + hex);
        //         } catch(e){
        //             send("[SIGN-BYTES-ERR] " + e);
        //         }
        //         return b;
        //     };
        //     send("[OK] Hooked Signature.toByteArray()");
        // } catch (e) {
        //     send("[ERROR] Failed to hook Signature: " + e);
        // }

        // Hook MessageDigest to capture SHA-256 hash of signature - DISABLED to prevent crash
        // try {
        //     var MessageDigest = Java.use("java.security.MessageDigest");
        //     var Base64 = Java.use("android.util.Base64");
        //     
        //     // Hook MessageDigest.getInstance
        //     MessageDigest.getInstance.overload("java.lang.String").implementation = function(algorithm: string) {
        //         var result = this.getInstance(algorithm);
        //         if (algorithm === "SHA-256") {
        //             // send("[SHA256] MessageDigest.getInstance called for SHA-256");
        //             
        //             // Hook digest method
        //             result.digest.overload().implementation = function() {
        //                 var hashBytes = this.digest();
        //                 var hashBase64 = Base64.encodeToString(hashBytes, 0);
        //                 // send("[SHA256-HASH] Final SHA-256 hash: " + hashBase64);
        //                 return hashBytes;
        //             };
        //         }
        //         return result;
        //     };
        //     
        //     // Also hook update method to see what data is being hashed
        //     MessageDigest.update.overload("[B").implementation = function(input: any) {
        //         var result = this.update(input);
        //         // send("[SHA256] MessageDigest.update called with " + input.length + " bytes");
        //         return result;
        //     };
        //     
        //     send("[OK] Hooked MessageDigest for SHA-256 capture");
        // } catch (e) {
        //     send("[ERROR] Failed to hook MessageDigest: " + e);
        // }

        // Hook Cipher.doFinal() to capture AES encryption result
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var Base64 = Java.use("android.util.Base64");
            
            // Hook Cipher.doFinal to capture encrypted data
            Cipher.doFinal.overload("[B").implementation = function(input: any) {
                var result = this.doFinal(input);
                var resultBase64 = Base64.encodeToString(result, 0);
                
                // Try to decode input as string to see what's being encrypted
                try {
                    // Convert byte array to string
                    var inputStr = "";
                    for (var i = 0; i < input.length; i++) {
                        inputStr += String.fromCharCode(input[i] & 0xFF);
                    }
                    
                    if (inputStr.length > 0 && inputStr.length < 50) {
                        send("[CIPHER-INPUT] " + inputStr + " (length: " + inputStr.length + ")");
                    }
                } catch (e) {
                    // Input might not be a string
                }
                
                send("[AES-ENCRYPT] " +"http://carmin-backend.appspot.com/rs/mo/" + resultBase64);
                send("[AES-DEBUG] Original result: " + resultBase64);
                send("[AES-DEBUG] Length: " + resultBase64.length);
                return result;
            };
            
            send("[OK] Hooked Cipher.doFinal() for AES encryption capture");
        } catch (e) {
            send("[ERROR] Failed to hook Cipher: " + e);
        }

        // Find and hook the actual class that contains f(String, String, String) method
        setTimeout(function() {
            send('[DEBUG] Starting to find class with f(String,String,String) method...');
            
            try {
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        // Look for classes that might contain the f method
                        if (className.indexOf('com.min.car') !== -1 || 
                            className.indexOf('d.c.a') !== -1 || 
                            className.indexOf('f') !== -1) {
                            
                            try {
                                var Cls = Java.use(className);
                                
                                // Check if this class has a static f method
                                if (Cls.f && Cls.f.overload) {
                                    try {
                                        var fOverload = Cls.f.overload('java.lang.String', 'java.lang.String', 'java.lang.String');
                                        
                                        // Hook the f method
                                        fOverload.implementation = function(str: string, str2: string, str3: string) {
                                            send('[F-INPUTS] class=' + className);
                                            send('[F-INPUTS] str=' + str + ' (makerId)');
                                            send('[F-INPUTS] str2=' + str2 + ' (app version)');
                                            send('[F-INPUTS] str3=' + str3 + ' (version app)');
                                            send('[F-INPUTS] str2+str3=' + str2 + str3 + ' (key material)');
                                            
                                            // Call original method
                                            var result = fOverload.call(Cls, str, str2, str3);
                                            send('[F-RESULT] ' + result);
                                            return result;
                                        };
                                        
                                        send('[OK] Hooked f(String,String,String) in: ' + className);
                                        
                                        // Also try to hook r method if it exists
                                        try {
                                            var rOverload = Cls.r.overload('java.lang.String');
                                            rOverload.implementation = function(seed: string) {
                                                send('[R-INPUT] class=' + className);
                                                send('[R-INPUT] seed=' + seed + ' (key material)');
                                                
                                                var result = rOverload.call(Cls, seed);
                                                send('[R-RESULT] ' + result);
                                                return result;
                                            };
                                            send('[OK] Hooked r(String) in: ' + className);
                                        } catch (e) {
                                            // r method doesn't exist or different signature
                                        }
                                        
                                    } catch (e) {
                                        // f method doesn't have the right signature
                                    }
                                }
                            } catch (e) {
                                // Class not accessible
                            }
                        }
                    },
                    onComplete: function() {
                        send('[DEBUG] Finished searching for f(String,String,String) method');
                    }
                });
            } catch (e) {
                send('[ERROR] Failed to enumerate classes: ' + e);
            }
        }, 2000); // Wait 2 seconds before searching




    });
} else {
    console.log("No Java VM in this process");
}
