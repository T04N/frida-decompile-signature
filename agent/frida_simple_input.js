Java.perform(function() {
    console.log("[+] Starting simple input capture script");
    
    // Helpers for consistent logging/compare
    function toHex(bytes) {
        try {
            return Array.prototype.map.call(bytes, function(x){
                return ('0'+(x & 0xff).toString(16)).slice(-2);
            }).join('').toUpperCase();
        } catch (e) { return ""; }
    }

    function toCsv(bytes) {
        try {
            return Array.prototype.map.call(bytes, function(x){ return (x|0); }).join(',');
        } catch (e) { return ""; }
    }

    function bytesToString(bytes) {
        try {
            var s = "";
            for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] & 0xFF);
            return s;
        } catch (e) { return ""; }
    }
    
    // Hook SecretKeySpec to capture AES key
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        var Base64 = Java.use('android.util.Base64');
        
        // Hook SecretKeySpec constructor
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
            try {
                if (algorithm && algorithm.toUpperCase() === 'AES') {
                    var b64 = Base64.encodeToString(keyBytes, 0);
                    var hex = Array.prototype.map.call(keyBytes, function(x){ 
                        return ('0'+(x & 0xff).toString(16)).slice(-2); 
                    }).join('').toUpperCase();
                    
                    // console.log('[AES-KEY] algo=' + algorithm + ' len=' + keyBytes.length + ' key.b64=' + b64);
                    // console.log('[AES-KEY] key.hex=' + hex);
                    
                    // Also log the key bytes as comma-separated values
                    var keyBytesStr = Array.prototype.map.call(keyBytes, function(x){ 
                        return x; 
                    }).join(',');
                    // console.log('[AES-KEY] key.bytes=' + keyBytesStr);
                }
            } catch (e) {
                // Ignore errors
            }
            return this.$init(keyBytes, algorithm);
        };
        
        console.log("[+] Hooked SecretKeySpec constructor");
    } catch (e) {
        console.log("[-] Failed to hook SecretKeySpec: " + e);
    }
    
    // Hook MessageDigest to capture key material
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        var Base64 = Java.use("android.util.Base64");
        
        // Hook MessageDigest.getInstance (support SHA-1 and SHA-256)
        var ExceptionCls = Java.use('java.lang.Exception');
        var ThreadCls = Java.use('java.lang.Thread');
        var sha256Accum = {};
        MessageDigest.getInstance.overload("java.lang.String").implementation = function(algorithm) {
            var result = this.getInstance(algorithm);
            if (algorithm === "SHA-1") {
                // Hook digest() for SHA-1 (kept for compatibility)
                result.digest.overload().implementation = function() {
                    var hashBytes = this.digest();
                    return hashBytes;
                };
            } else if (algorithm === "SHA-256") {
                try { console.log('[MD] getInstance("SHA-256")'); } catch (eLog) {}
                // Hook digest() and print only when called from d.c.a.f.b.g
                try {
                    result.digest.overload().implementation = function() {
                        var out = this.digest();
                        try {
                            var st = ExceptionCls.$new().getStackTrace();
                            var fromBg = false;
                            for (var i = 0; i < st.length; i++) {
                                var fqn = st[i].toString();
                                if (fqn.indexOf('d.c.a.f.b.g') !== -1) { fromBg = true; break; }
                            }
                            if (fromBg) {
                                var b64 = Base64.encodeToString(out, 0);
                                console.log('[SHA256@b.g] piece=' + b64);
                                try {
                                    var tid = ThreadCls.currentThread().getId();
                                    var key = '' + tid;
                                    sha256Accum[key] = (sha256Accum[key] || '') + b64;
                                    console.log('[SHA256@b.g] concat_so_far=' + sha256Accum[key]);
                                } catch (e2) {}
                            }
                        } catch (e1) {}
                        return out;
                    };
                } catch (e0) {}
            }
            return result;
        };

        // Also hook update([B) to see input from Signature.toByteArray() used by g(Context)
        try {
            MessageDigest.update.overload('[B').implementation = function(input) {
                var ret = this.update(input);
                try {
                    var st = ExceptionCls.$new().getStackTrace();
                    for (var i = 0; i < st.length; i++) {
                        if (st[i].toString().indexOf('d.c.a.f.b.g') !== -1) {
                            console.log('[SHA256@b.g] update bytes len=' + (input ? input.length : 0));
                            break;
                        }
                    }
                } catch (e) {}
                return ret;
            };
        } catch (eUpd) {}

        // Hook Base64.encodeToString and only log when called from b.g
        try {
            Base64.encodeToString.overload('[B', 'int').implementation = function(bytes, flags) {
                var out = this.encodeToString(bytes, flags);
                try {
                    var st = ExceptionCls.$new().getStackTrace();
                    for (var i = 0; i < st.length; i++) {
                        if (st[i].toString().indexOf('d.c.a.f.b.g') !== -1) {
                            if (bytes && bytes.length === 32) { // digest length
                                console.log('[B64@b.g] piece=' + out);
                            }
                            break;
                        }
                    }
                } catch (e) {}
                return out;
            };
        } catch (eB64) {}
        
        // Hook update method to see what data is being hashed
        MessageDigest.update.overload("[B").implementation = function(input) {
            var result = this.update(input);
            try {
                var inputStr = "";
                for (var i = 0; i < input.length; i++) {
                    inputStr += String.fromCharCode(input[i] & 0xFF);
                }
                // console.log("[SHA1-INPUT] " + inputStr + " (length: " + input.length + ")");
            } catch (e) {
                // Ignore
            }
            return result;
        };
        
        console.log("[+] Hooked MessageDigest for SHA-1 capture");
    } catch (e) {
        console.log("[-] Failed to hook MessageDigest: " + e);
    }
    
    // Hook Cipher.init to capture the actual key being used
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        var Base64 = Java.use("android.util.Base64");
        var cipherKeyMap = {};
        function getCipherId(self) {
            try { return self.$h.value; } catch (e) {}
            try { return self.toString(); } catch (e2) {}
            return Math.random().toString(36).slice(2);
        }
        
        // Hook all init overloads
        Cipher.init.overload("int", "java.security.Key").implementation = function(mode, key) {
            try {
                if (key.getAlgorithm() === "AES") {
                    var keyBytes = key.getEncoded();
                    var id = getCipherId(this);
                    cipherKeyMap[id] = keyBytes;
                    // console.log("[AES-KEY-USED] mode=" + mode + " algo=" + key.getAlgorithm() + " len=" + keyBytes.length);
                    // console.log("[AES-KEY-USED] key.b64=" + Base64.encodeToString(keyBytes, 0));
                    // console.log("[AES-KEY-USED] key.hex=" + toHex(keyBytes));
                    // console.log("[AES-KEY-USED] key.bytes=" + toCsv(keyBytes));
                }
            } catch (e) {
                console.log("[AES-KEY-USED] Error: " + e);
            }
            return this.init(mode, key);
        };
        
        // Also hook the overload with AlgorithmParameterSpec
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(mode, key, params) {
            try {
                if (key.getAlgorithm() === "AES") {
                    var keyBytes = key.getEncoded();
                    var id = getCipherId(this);
                    cipherKeyMap[id] = keyBytes;
                    console.log("[AES-KEY-USED] mode=" + mode + " algo=" + key.getAlgorithm() + " len=" + keyBytes.length);
                    console.log("[AES-KEY-USED] key.b64=" + Base64.encodeToString(keyBytes, 0));
                    console.log("[AES-KEY-USED] key.hex=" + toHex(keyBytes));
                    console.log("[AES-KEY-USED] key.bytes=" + toCsv(keyBytes));
                }
            } catch (e) {
                console.log("[AES-KEY-USED] Error: " + e);
            }
            return this.init(mode, key, params);
        };
        
        console.log("[+] Hooked Cipher.init (all overloads)");
    } catch (e) {
        console.log("[-] Failed to hook Cipher.init: " + e);
    }

    // Hook Cipher.doFinal only - safest approach
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        var Base64 = Java.use("android.util.Base64");
        
        Cipher.doFinal.overload("[B").implementation = function(input) {
            var id = (function(self){ try{return self.$h.value;}catch(e){} try{return self.toString();}catch(e2){} return "?"; })(this);
            var result = this.doFinal(input);
            try {
                if (typeof cipherKeyMap !== 'undefined') {
                    var k = cipherKeyMap[id];
                    if (k) {
                        console.log("[DOFINAL] key.b64=" + Base64.encodeToString(k, 0));
                        console.log("[DOFINAL] key.hex=" + toHex(k));
                        console.log("[DOFINAL] key.bytes=" + toCsv(k));
                    } else {
                        console.log("[DOFINAL] key=UNKNOWN for this Cipher instance");
                    }
                }
            } catch (e) {}

            // Only log AES-ENCRYPT when input is exactly 16 bytes
            if (input.length === 16) {
                var resultBase64 = Base64.encodeToString(result, 0);
                console.log("[AES-ENCRYPT] Input: 16 bytes, Result: " + resultBase64);
                console.log("[AES-URL] http://carmin-backend.appspot.com/rs/mo/" + resultBase64);
            }
            return result;
        };
        
        console.log("[+] Hooked Cipher.doFinal");
    } catch (e) {
        console.log("[-] Failed to hook Cipher: " + e);
    }
    

    // Compute equivalent of d.c.a.f.b.g(Context) (no direct method call)
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var Application = Java.use('android.app.Application');
        var Base64_ = Java.use('android.util.Base64');
        var MessageDigest_ = Java.use('java.security.MessageDigest');

        function computeBySigningInfo(ctx_) {
            try {
                var pm_ = ctx_.getPackageManager();
                var pkg_ = ctx_.getPackageName();
                var GET_SIGNATURES = 64;
                var GET_SIGNING_CERTIFICATES = 0x00004000;
                var flags_ = GET_SIGNATURES | GET_SIGNING_CERTIFICATES;

                // Handle API 33+: getPackageInfo(String, PackageManager.PackageInfoFlags)
                var pi_ = null;
                try {
                    var overloadInt = pm_.getPackageInfo.overload('java.lang.String', 'int');
                    pi_ = pm_.getPackageInfo(pkg_, flags_);
                } catch (eOver) {
                    try {
                        var PkgInfoFlags = Java.use('android.content.pm.PackageManager$PackageInfoFlags');
                        var LongCls = Java.use('java.lang.Long');
                        var flagsObj = PkgInfoFlags.of(LongCls.valueOf(flags_));
                        pi_ = pm_.getPackageInfo(pkg_, flagsObj);
                    } catch (eOver2) {
                        console.log('[-] getPackageInfo failed: ' + eOver2);
                        return '';
                    }
                }
                var parts_ = [];

                // Try legacy signatures field
                try {
                    var sigField = null;
                    try { sigField = pi_['signatures']; } catch (eSF) {}
                    var sigs_ = sigField ? (sigField.value || sigField) : null;
                    if (sigs_ && sigs_.length > 0) {
                        for (var i_ = 0; i_ < sigs_.length; i_++) {
                            var md_ = MessageDigest_.getInstance('SHA-256');
                            md_.update(sigs_[i_].toByteArray());
                            parts_.push(Base64_.encodeToString(md_.digest(), 0));
                        }
                    }
                } catch (eSig) { /* ignore */ }

                // Try SigningInfo API 28+
                try {
                    if (parts_.length === 0) {
                        var si_ = null;
                        try { si_ = pi_['signingInfo']; si_ = si_ && si_.value ? si_.value : si_; } catch (eSI) {}
                        if (!si_ && pi_.getSigningInfo) {
                            try { si_ = pi_.getSigningInfo(); } catch (eSIM) {}
                        }
                        if (si_) {
                            var arr_ = null;
                            try { arr_ = si_.getApkContentsSigners(); } catch (eACS) {}
                            if (!arr_ || arr_.length === 0) {
                                try { arr_ = si_.getSigningCertificateHistory(); } catch (eSCH) {}
                            }
                            if (arr_) {
                                for (var j_ = 0; j_ < arr_.length; j_++) {
                                    var md2_ = MessageDigest_.getInstance('SHA-256');
                                    md2_.update(arr_[j_].toByteArray());
                                    parts_.push(Base64_.encodeToString(md2_.digest(), 0));
                                }
                            }
                        }
                    }
                } catch (eSIWrap) { /* ignore */ }

                var result_ = parts_.join('').trim();
                console.log('[g(Context) EQUIV] ' + result_);
                return result_;
            } catch (e) {
                console.log('[-] computeBySigningInfo error: ' + e);
                return '';
            }
        }

        function runWithContext(ctx_) {
            if (!ctx_) return;
            computeBySigningInfo(ctx_);
        }

        var app_ = ActivityThread.currentApplication();
        if (app_) {
            runWithContext(app_.getApplicationContext());
        } else {
            var got_ = false;
            try {
                Java.choose('android.app.Application', {
                    onMatch: function (inst) {
                        if (!got_) {
                            got_ = true;
                            runWithContext(inst.getApplicationContext());
                        }
                    }, onComplete: function () {}
                });
            } catch (e1) {}

            if (!got_) {
                try {
                    Application.attach.overload('android.content.Context').implementation = function (ctx) {
                        this.attach(ctx);
                        try { runWithContext(ctx.getApplicationContext()); } catch (e2) {}
                    };
                    console.log('[*] Waiting Application.attach for context...');
                } catch (e3) {
                    console.log('[-] hook Application.attach failed: ' + e3);
                }
            }
        }
    } catch (e_) {
        console.log('[-] Error setting up g(Context) capture: ' + e_);
    }

    console.log("[+] Script loaded successfully");
});
