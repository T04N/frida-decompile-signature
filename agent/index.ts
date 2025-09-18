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

        // Reflection-based lightweight hook to capture any static f(String,String,String) args (no class filter)
        try {
            var Method = Java.use("java.lang.reflect.Method");
            var Modifier = Java.use("java.lang.reflect.Modifier");
            var StringCls = Java.use("java.lang.String");
            var origInvoke = Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;');
            origInvoke.implementation = function(receiver: any, argsArr: any) {
                try {
                    var name = this.getName();
                    if (name === 'f' && argsArr && argsArr.length === 3) {
                        // Check it is static and has (String,String,String) and returns String
                        var isStatic = Modifier.isStatic(this.getModifiers());
                        if (isStatic) {
                            var ptypes = this.getParameterTypes();
                            var rtype = this.getReturnType();
                            if (ptypes.length === 3 &&
                                ptypes[0].getName() === 'java.lang.String' &&
                                ptypes[1].getName() === 'java.lang.String' &&
                                ptypes[2].getName() === 'java.lang.String' &&
                                rtype.getName() === 'java.lang.String') {
                                var s0 = argsArr[0] ? StringCls.$new(argsArr[0]).toString() : 'null';
                                var s1 = argsArr[1] ? StringCls.$new(argsArr[1]).toString() : 'null';
                                var s2 = argsArr[2] ? StringCls.$new(argsArr[2]).toString() : 'null';
                                var decl = this.getDeclaringClass();
                                var declName = decl ? decl.getName() : 'unknown';
                                send('[F-ARGS] class=' + declName + ' str=' + s0 + ' str2=' + s1 + ' str3=' + s2);
                            }
                        }
                    }
                } catch (_) {}
                return origInvoke.call(this, receiver, argsArr);
            };
            send('[OK] Hooked Method.invoke for f(String,String,String) arg capture');
        } catch (e) {
            send('[ERROR] Failed to hook Method.invoke: ' + e);
        }

        // Robust direct hooks for d.c.a.f.b: f(String,String,String) and r(String) with retry until class loads
        try {
            var hookBOnce = function() {
                try {
                    var Bcls = Java.use('d.c.a.f.b');
                    // Hook static f(String,String,String)
                    try {
                        var fOver = Bcls.f.overload('java.lang.String', 'java.lang.String', 'java.lang.String');
                        fOver.implementation = function(str: string, str2: string, str3: string) {
                            try { send('[F-ARGS-DIRECT] str=' + str + ' str2=' + str2 + ' str3=' + str3); } catch (_) {}
                            // For static methods, `this` is the class wrapper; call original via overload
                            return fOver.call(this, str, str2, str3);
                        };
                        send('[OK] Hooked d.c.a.f.b.f(String,String,String)');
                    } catch (fe) {
                        send('[WARN] d.c.a.f.b.f overload not ready: ' + fe);
                        throw fe;
                    }

                    // Hook static r(String)
                    try {
                        var rOver = Bcls.r.overload('java.lang.String');
                        rOver.implementation = function(seed: string) {
                            try { send('[R-ARG] seed=' + seed); } catch (_) {}
                            return rOver.call(this, seed);
                        };
                        send('[OK] Hooked d.c.a.f.b.r(String)');
                    } catch (re) {
                        send('[WARN] d.c.a.f.b.r overload not ready: ' + re);
                        // Do not throw; f() is primary target
                    }

                    return true;
                } catch (e) {
                    return false;
                }
            };

            if (!hookBOnce()) {
                var tries = 0;
                var maxTries = 10;
                var t = setInterval(function() {
                    if (hookBOnce() || ++tries >= maxTries) {
                        clearInterval(t);
                        if (tries >= maxTries) {
                            send('[WARN] Stop retrying hook for d.c.a.f.b after ' + tries + ' attempts');
                        }
                    }
                }, 500);
                send('[INFO] Will retry hooking d.c.a.f.b up to ' + maxTries + ' times');
            }
        } catch (e) {
            send('[ERROR] Failed to init direct hooks for d.c.a.f.b: ' + e);
        }

        // Direct hook for static b.f(String,String,String) discovered in decompiled code (d.c.a.f.b)
        try {
            var B = Java.use('d.c.a.f.b');
            var f3 = B.f.overload('java.lang.String', 'java.lang.String', 'java.lang.String');
            f3.implementation = function(str: string, str2: string, str3: string) {
                try { send('[F-ARGS-DIRECT] str=' + str + ' str2=' + str2 + ' str3=' + str3); } catch (_) {}
                return f3.call(B, str, str2, str3);
            };
            send('[OK] Hooked d.c.a.f.b.f(String,String,String)');
        } catch (e) {
            send('[WARN] d.c.a.f.b.f not available yet, will retry shortly: ' + e);
            setTimeout(function() {
                try {
                    var B2 = Java.use('d.c.a.f.b');
                    var f32 = B2.f.overload('java.lang.String', 'java.lang.String', 'java.lang.String');
                    f32.implementation = function(str: string, str2: string, str3: string) {
                        try { send('[F-ARGS-DIRECT] str=' + str + ' str2=' + str2 + ' str3=' + str3); } catch (_) {}
                        return f32.call(B2, str, str2, str3);
                    };
                    send('[OK] Hooked d.c.a.f.b.f(String,String,String) on retry');
                } catch (e2) {
                    send('[ERROR] Failed to hook d.c.a.f.b.f after retry: ' + e2);
                }
            }, 1500);
        }

        // Hook static method r(String) to capture input secret seed
        // try {
        //     // Try likely classes first, then fall back to enumerate
        //     var candidates = [
        //         "com.min.car.security.Security",
        //         "com.min.car.crypto.CryptoUtils",
        //         "com.min.car.utils.Utils",
        //         "com.min.car.helper.Helper"
        //     ];

        //     var hookedR = false;

        //     for (var i = 0; i < candidates.length; i++) {
        //         try {
        //             var Cls = Java.use(candidates[i]);
        //             var rOver = Cls.r.overload("java.lang.String");
        //             rOver.implementation = function(secretStr: string) {
        //                 try { send("[R] secret input: " + secretStr); } catch (_) {}
        //                 return rOver.call(Cls, secretStr);
        //             };
        //             send("[OK] Hooked r(String) in: " + candidates[i]);
        //             hookedR = true;
        //             break;
        //         } catch (_) {
        //             // continue
        //         }
        //     }

        //     if (!hookedR) {
        //         Java.enumerateLoadedClasses({
        //             onMatch: function(className) {
        //                 if (hookedR) return; // already done
        //                 if (className.indexOf("com.min.car") !== -1) {
        //                     try {
        //                         var C = Java.use(className);
        //                         // Ensure method r with single String exists
        //                         var over = C.r && C.r.overload && C.r.overload("java.lang.String");
        //                         if (over) {
        //                             over.implementation = function(s: string) {
        //                                 try { send("[R] secret input: " + s + " (class=" + className + ")"); } catch (_) {}
        //                                 return over.call(C, s);
        //                             };
        //                             send("[OK] Hooked r(String) in: " + className);
        //                             hookedR = true;
        //                         }
        //                     } catch (_) {}
        //                 }
        //             },
        //             onComplete: function() {
        //                 if (!hookedR) {
        //                     send("[WARN] Could not find r(String) to hook");
        //                 }
        //             }
        //         });
        //     }
        // } catch (e) {
        //     send("[ERROR] Failed to hook r(String): " + e);
        // }
    });
} else {
    console.log("No Java VM in this process");
}
