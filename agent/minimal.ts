import Java from "frida-java-bridge";

if (Java.available) {
    Java.perform(() => {
        send({
            type: "status", 
            message: "Minimal agent loaded"
        });

        // Chỉ hook Cipher.doFinal để bắt kết quả mã hóa
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var Base64 = Java.use("android.util.Base64");
            
            Cipher.doFinal.overload("[B").implementation = function(input: any) {
                var result = this.doFinal(input);
                var resultBase64 = Base64.encodeToString(result, 0);
                send("[AES-ENCRYPT] " + resultBase64);
                return result;
            };
            
            send("[OK] Hooked Cipher.doFinal()");
        } catch (e) {
            send("[ERROR] Failed to hook Cipher: " + e);
        }
    });
} else {
    console.log("No Java VM in this process");
}
