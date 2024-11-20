package com.gifty.authservice.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * Token şifreleme ve çözme işlemleri için yardımcı sınıf.
 */
@Component
public class TokenEncryptionService {

    private final SecretKey key;

    /**
     * Constructor ile şifreleme anahtarını yükler.
     *
     * @param base64SecretKey Şifreleme anahtarı (application.properties'den alınır)
     */
    // Base64 şifrelenmiş bir anahtarı çözerek kullanıyoruz.
    public TokenEncryptionService(@Value("${refresh.token.encryption.secret}") String base64SecretKey) {
        byte[] decodedKey = Base64.getDecoder().decode(base64SecretKey);
        if (decodedKey.length != 16 && decodedKey.length != 24 && decodedKey.length != 32) {
            throw new IllegalArgumentException("Invalid AES key length: " + decodedKey.length);
        }
        this.key = new SecretKeySpec(decodedKey, "AES");
    }

    /**
     * Verilen token'ı şifreler.
     *
     * @param token Şifrelenecek token
     * @return Şifrelenmiş token
     * @throws Exception Şifreleme sırasında oluşabilecek hatalar
     */
    public String encrypt(String token) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(token.getBytes()));
    }

    /**
     * Şifrelenmiş token'ı çözer.
     *
     * @param encryptedToken Şifrelenmiş token
     * @return Orijinal token
     * @throws Exception Şifre çözme sırasında oluşabilecek hatalar
     */
    public String decrypt(String encryptedToken) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedToken)));
    }
}
