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
                    send("[SIGN-BYTES-TESTING] base64=" + b64 + " hex=" + hex);
                } catch(e){
                    // send("[SIGN-BYTES-ERR] " + e);
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
                    // send("[SHA256] MessageDigest.getInstance called for SHA-256");
                    
                    // Hook digest method
                    result.digest.overload().implementation = function() {
                        var hashBytes = this.digest();
                        var hashBase64 = Base64.encodeToString(hashBytes, 0);
                        // send("[SHA256-HASH] Final SHA-256 hash: " + hashBase64);
                        return hashBytes;
                    };
                }
                return result;
            };
            
            // Also hook update method to see what data is being hashed
            MessageDigest.update.overload("[B").implementation = function(input: any) {
                var result = this.update(input);
                // send("[SHA256] MessageDigest.update called with " + input.length + " bytes");
                return result;
            };
            
            send("[OK] Hooked MessageDigest for SHA-256 capture");
        } catch (e) {
            send("[ERROR] Failed to hook MessageDigest: " + e);
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
                    // Capture static c(Context,String) -> String to get `str` without class discovery
                    if (name === 'c' && argsArr && argsArr.length === 2) {
                        var isStaticC = Modifier.isStatic(this.getModifiers());
                        if (isStaticC) {
                            var pC = this.getParameterTypes();
                            var rC = this.getReturnType();
                            if (pC.length === 2 &&
                                pC[0].getName() === 'android.content.Context' &&
                                pC[1].getName() === 'java.lang.String' &&
                                rC.getName() === 'java.lang.String') {
                                var declC = this.getDeclaringClass();
                                var declNameC = declC ? declC.getName() : 'unknown';
                                var strArg = argsArr[1] ? StringCls.$new(argsArr[1]).toString() : 'null';
                                send('[C-ARGS] class=' + declNameC + ' str=' + strArg);
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
        try {
            var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
            var Base64 = Java.use('android.util.Base64');

            // SecretKeySpec(byte[] key, String algorithm)
            SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes: any, algorithm: string) {
                try {
                    if (algorithm && algorithm.toUpperCase() === 'AES') {
                        var b64 = Base64.encodeToString(keyBytes, 0);
                        var hex = Array.prototype.map.call(keyBytes, function(x){ return ('0'+(x & 0xff).toString(16)).slice(-2); }).join('').toUpperCase();
                        send('[AES-KEY] algo=' + algorithm + ' len=' + keyBytes.length + ' key.b64=' + b64 + ' key.hex=' + hex);
                    }
                } catch (_) {}
                return this.$init(keyBytes, algorithm);
            };


            SecretKeySpec.$init.overload('[B', 'int', 'int', 'java.lang.String').implementation = function(keyBytes2: any, offset: number, len: number, algorithm2: string) {
                try {
                    if (algorithm2 && algorithm2.toUpperCase() === 'AES') {
                        // Extract slice manually for logging
                        var slice = Java.array('byte', keyBytes2).slice(offset, offset + len);
                        var b64s = Base64.encodeToString(slice, 0);
                        var hexs = Array.prototype.map.call(slice, function(x){ return ('0'+(x & 0xff).toString(16)).slice(-2); }).join('').toUpperCase();
                        send('[AES-KEY] algo=' + algorithm2 + ' len=' + len + ' key.b64=' + b64s + ' key.hex=' + hexs);
                    }
                } catch (_) {}
                return this.$init(keyBytes2, offset, len, algorithm2);
            };

            send('[OK] Hooked SecretKeySpec constructors for AES key capture');
        } catch (e) {
            send('[ERROR] Failed to hook SecretKeySpec: ' + e);
        }

        // Hook Cipher.init to capture the EXACT key used at runtime
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var SecretKeySpecCls = Java.use('javax.crypto.spec.SecretKeySpec');
            var Base64 = Java.use("android.util.Base64");
            
            Cipher.init.overload('int', 'java.security.Key').implementation = function(mode: number, key: any) {
                try {
                
                    if (mode === 1 && key) {
                        var ks = Java.cast(key, SecretKeySpecCls);
                        var kbytes = ks.getEncoded();
                        var kb64 = Base64.encodeToString(kbytes, 0);
                        var khex = Array.prototype.map.call(kbytes, function(x){ return ('0'+(x & 0xff).toString(16)).slice(-2); }).join('').toUpperCase();
                        send('[AES-KEY-RUNTIME] len=' + kbytes.length + ' key.b64=' + kb64 + ' key.hex=' + khex);
                    }
                } catch (_) {}
                return this.init(mode, key);
            };
            
            send('[OK] Hooked Cipher.init for runtime key capture');
        } catch (e) {
            send('[ERROR] Failed to hook Cipher.init: ' + e);
        }

     
    
        try {
            var hookedFMap: any = (globalThis as any).__hookedFMap || {};
            (globalThis as any).__hookedFMap = hookedFMap;

            var hookAllF = function() {
                try {
                    var classes = Java.enumerateLoadedClassesSync();
                    var ModifierAll = Java.use('java.lang.reflect.Modifier');
                    for (var i = 0; i < classes.length; i++) {
                        var cn = classes[i];
                        if (hookedFMap[cn]) continue;
                        try {
                            var ClsAny: any = Java.use(cn);
                            if (!ClsAny || !ClsAny.f || !ClsAny.f.overload) continue;
                            var overF = null;
                            try {
                                overF = ClsAny.f.overload('java.lang.String','java.lang.String','java.lang.String');
                            } catch (_) { continue; }
                            if (!overF) continue;

                            // Verify via reflection: static and return String
                            var methods = ClsAny.class.getDeclaredMethods();
                            var ok = false;
                            for (var k = 0; k < methods.length; k++) {
                                var m = methods[k];
                                if (m.getName() !== 'f') continue;
                                var p = m.getParameterTypes();
                                var r = m.getReturnType();
                                if (p.length === 3 && p[0].getName()==='java.lang.String' && p[1].getName()==='java.lang.String' && p[2].getName()==='java.lang.String' && r.getName()==='java.lang.String' && ModifierAll.isStatic(m.getModifiers())) {
                                    ok = true; break;
                                }
                            }
                            if (!ok) continue;

                            (function(cnLocal: string, ClsLocal: any, overLocal: any){
                                overLocal.implementation = function(s0: string, s1: string, s2: string) {
                                    try { send('[F-ARGS-ENUM] class=' + cnLocal + ' str=' + s0 + ' str2=' + s1 + ' str3=' + s2); } catch (_) {}
                                    return overLocal.call(ClsLocal, s0, s1, s2);
                                };
                            })(cn, ClsAny, overF);

                            hookedFMap[cn] = true;
                            // send('[OK] Hooked f(String,String,String) on ' + cn);
                        } catch (_) {}
                    }
                } catch (_) {}
            };

            hookAllF();
            setInterval(hookAllF, 2000);
        } catch (e) {}

        // Enumerate and hook any static c(Context,String):String to capture str
        try {
            var hookedCMap: any = (globalThis as any).__hookedCMap || {};
            (globalThis as any).__hookedCMap = hookedCMap;

            var hookAllC = function() {
                try {
                    var classes = Java.enumerateLoadedClassesSync();
                    for (var i = 0; i < classes.length; i++) {
                        var cn = classes[i];
                        if (hookedCMap[cn]) continue;
                        try {
                            var Cls: any = Java.use(cn);
                            if (!Cls || !Cls.c || !Cls.c.overload) continue;
                            var overC: any = null;
                            try {
                                overC = Cls.c.overload('android.content.Context', 'java.lang.String');
                            } catch (_) {
                                continue;
                            }
                            if (!overC) continue;

                            // Verify static via reflection
                            var methods = Cls.class.getDeclaredMethods();
                            var Modifier = Java.use('java.lang.reflect.Modifier');
                            var isStaticMatch = false;
                            for (var k = 0; k < methods.length; k++) {
                                var m = methods[k];
                                if (m.getName() === 'c') {
                                    var p = m.getParameterTypes();
                                    var r = m.getReturnType();
                                    if (p.length === 2 && p[0].getName() === 'android.content.Context' && p[1].getName() === 'java.lang.String' && r.getName() === 'java.lang.String') {
                                        if (Modifier.isStatic(m.getModifiers())) {
                                            isStaticMatch = true;
                                            break;
                                        }
                                    }
                                }
                            }
                            if (!isStaticMatch) continue;

                            overC.implementation = function(ctx: any, s: string) {
                                try { send('[C-ARGS] class=' + cn + ' str=' + s); } catch (_) {}
                                return overC.call(Cls, ctx, s);
                            };
                            hookedCMap[cn] = true;
                            // send('[OK] Hooked c(Context,String) on ' + cn);
                        } catch (_) {}
                    }
                } catch (err) {
                    // ignore
                }
            };

            hookAllC();
            setInterval(hookAllC, 2000);
        } catch (e) {}

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
