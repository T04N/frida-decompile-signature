package simplesolution.dev.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESEncryption {

    // Base64 của "J1YXhfvIIT9Fmgke" (16 bytes)
    // Lưu ý: nếu bạn muốn truyền thẳng ASCII thì bỏ decode B64 và dùng getBytes().
    private static final String KEY_B64 = Base64.getEncoder()
            .encodeToString("J1YXhfvIIT9Fmgke".getBytes(StandardCharsets.UTF_8));

    public static void main(String... args) {
        try {
            String secretKeyB64 = KEY_B64; // "SjFZWGhmdkkJVDlGbWdrZQ==" tương ứng "J1YXhfvIIT9Fmgke"
            String dataToEncrypt = "5674505103998976";
            // ví dụ ciphertext URL-safe từ app: thay bằng chuỗi của bạn nếu cần thử giải mã
            String dataToDecrypt = "23ApXLavVjEcUNBKIJooVHlPP8-xGIbd2lzIiZ85aRM=";

            System.out.println("ENC std:  " + encryptCBCStdB64(secretKeyB64, dataToEncrypt));
            System.out.println("ENC url:  " + encryptCBCUrlB64(secretKeyB64, dataToEncrypt));

            System.out.println("DEC std:  " + decryptCBC(secretKeyB64, dataToDecrypt));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static SecretKeySpec getKeyFromB64(String keyB64) {
        byte[] key = Base64.getDecoder().decode(keyB64);
        if (key.length != 16)
            throw new IllegalArgumentException("Key must be 16 bytes");
        return new SecretKeySpec(key, "AES");
    }

    private static IvParameterSpec getIvSameAsKey(SecretKeySpec key) {
        return new IvParameterSpec(key.getEncoded()); // IV = key (theo log app)
    }

    public static String encryptCBCStdB64(String keyB64, String plaintext) throws Exception {
        SecretKeySpec key = getKeyFromB64(keyB64);
        IvParameterSpec iv = getIvSameAsKey(key);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct); // chuẩn
    }

    public static String encryptCBCUrlB64(String keyB64, String plaintext) throws Exception {
        SecretKeySpec key = getKeyFromB64(keyB64);
        IvParameterSpec iv = getIvSameAsKey(key);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().encodeToString(ct); // URL-safe (như app dùng trong URL)
    }

    public static String decryptCBC(String keyB64, String ciphertextB64) {
        try {
            SecretKeySpec key = getKeyFromB64(keyB64);
            IvParameterSpec iv = getIvSameAsKey(key);

            byte[] ct;
            try {
                ct = Base64.getUrlDecoder().decode(ciphertextB64);
            } catch (IllegalArgumentException e) {
                ct = Base64.getDecoder().decode(ciphertextB64);
            }

            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] pt = c.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}