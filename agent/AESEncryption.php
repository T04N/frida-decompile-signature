<?php

class AESEncryption
{
    // Base64 of "J1YXhfvIIT9Fmgke" (16 bytes)
    private static $KEY_B64 = '';

    public static function init()
    {
        self::$KEY_B64 = base64_encode('J1YXhfvIIT9Fmgke');
    }

    public static function main()
    {
        try {
            $secretKeyB64 = self::$KEY_B64; // "SjFZWGhmdkkJVDlGbWdrZQ==" corresponds to "J1YXhfvIIT9Fmgke"
            $dataToEncrypt = "5682946392457216";
            // Example ciphertext URL-safe from app
            $dataToDecrypt = "67oZ0k4B1KZOOKsYYAknniFebTNBSqCWhBDJVZjWTX8=";

            echo "ENC std:  " . self::encryptCBCStdB64($secretKeyB64, $dataToEncrypt) . "\n";
            echo "ENC url:  " . self::encryptCBCUrlB64($secretKeyB64, $dataToEncrypt) . "\n";
            echo "DEC std:  " . self::decryptCBC($secretKeyB64, $dataToDecrypt) . "\n";
        } catch (Exception $ex) {
            echo $ex->getMessage() . "\n";
        }
    }

    private static function getKeyFromB64($keyB64)
    {
        $key = base64_decode($keyB64);
        if (strlen($key) !== 16) {
            throw new InvalidArgumentException("Key must be 16 bytes");
        }
        return $key;
    }

    private static function getIvSameAsKey($key)
    {
        return $key; // IV = key (as per app logic)
    }

    public static function encryptCBCStdB64($keyB64, $plaintext)
    {
        try {
            $key = self::getKeyFromB64($keyB64);
            $iv = self::getIvSameAsKey($key);
            $ciphertext = openssl_encrypt(
                $plaintext,
                'AES-128-CBC',
                $key,
                OPENSSL_RAW_DATA,
                $iv
            );
            if ($ciphertext === false) {
                throw new Exception("Encryption failed");
            }
            return base64_encode($ciphertext); // Standard Base64
        } catch (Exception $e) {
            throw new Exception("Encryption error: " . $e->getMessage());
        }
    }

    public static function encryptCBCUrlB64($keyB64, $plaintext)
    {
        try {
            $key = self::getKeyFromB64($keyB64);
            $iv = self::getIvSameAsKey($key);
            $ciphertext = openssl_encrypt(
                $plaintext,
                'AES-128-CBC',
                $key,
                OPENSSL_RAW_DATA,
                $iv
            );
            if ($ciphertext === false) {
                throw new Exception("Encryption failed");
            }
            // URL-safe Base64
            return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($ciphertext));
        } catch (Exception $e) {
            throw new Exception("Encryption error: " . $e->getMessage());
        }
    }

    public static function decryptCBC($keyB64, $ciphertextB64)
    {
        try {
            $key = self::getKeyFromB64($keyB64);
            $iv = self::getIvSameAsKey($key);

            // Try URL-safe decode first, fall back to standard Base64
            $ct = base64_decode(str_replace(['-', '_'], ['+', '/'], $ciphertextB64), true);
            if ($ct === false) {
                $ct = base64_decode($ciphertextB64, true);
            }
            if ($ct === false) {
                throw new Exception("Invalid Base64 encoding");
            }

            $plaintext = openssl_decrypt(
                $ct,
                'AES-128-CBC',
                $key,
                OPENSSL_RAW_DATA,
                $iv
            );
            if ($plaintext === false) {
                throw new Exception("Decryption failed");
            }
            return $plaintext;
        } catch (Exception $e) {
            echo "Decryption error: " . $e->getMessage() . "\n";
            return null;
        }
    }
}

// Initialize and run
AESEncryption::init();
AESEncryption::main();
