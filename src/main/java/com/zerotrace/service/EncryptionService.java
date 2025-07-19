package com.zerotrace.service;

import com.zerotrace.crypto.AESEncryption;
import com.zerotrace.crypto.KeyDerivation;
import org.bouncycastle.crypto.CryptoException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class EncryptionService {

    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final int KEY_LENGTH = 256; // bits
    private static final int IV_LENGTH = 16; // bytes for GCM
    private static final int SALT_LENGTH = 64; // bytes
    private static final int TAG_LENGTH = 16; // bytes for GCM authentication

    @Value("${crypto.wallet.security.encryption.master-key}")
    private String masterKey;

    @Value("${crypto.wallet.security.encryption.key-derivation.iterations}")
    private int iterations;

    private final SecureRandom secureRandom = new SecureRandom();
    private final AESEncryption aesEncryption = new AESEncryption();
    private final KeyDerivation keyDerivation = new KeyDerivation();

    /**
     * Encrypts sensitive data using AES-256-GCM with PBKDF2 key derivation
     */
    public String encryptSensitiveData(String plaintext, String userPassword) throws CryptoException {
        try {
            // Generate random salt
            byte[] salt = new byte[SALT_LENGTH];
            secureRandom.nextBytes(salt);

            // Derive key from master key + user password + salt
            String combinedKey = masterKey + userPassword;
            SecretKeySpec derivedKey = keyDerivation.deriveKey(
                    combinedKey.getBytes(StandardCharsets.UTF_8),
                    salt,
                    iterations,
                    KEY_LENGTH
            );

            // Generate random IV
            byte[] iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);

            // Encrypt using AES-256-GCM
            byte[] encryptedData = aesEncryption.encryptGCM(
                    plaintext.getBytes(StandardCharsets.UTF_8),
                    derivedKey,
                    iv
            );

            // Combine salt + iv + encrypted data for storage
            byte[] combined = new byte[SALT_LENGTH + IV_LENGTH + encryptedData.length];
            System.arraycopy(salt, 0, combined, 0, SALT_LENGTH);
            System.arraycopy(iv, 0, combined, SALT_LENGTH, IV_LENGTH);
            System.arraycopy(encryptedData, 0, combined, SALT_LENGTH + IV_LENGTH, encryptedData.length);

            return Base64.getEncoder().encodeToString(combined);

        } catch (Exception e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    /**
     * Decrypts sensitive data
     */
    public String decryptSensitiveData(String encryptedData, String userPassword) throws CryptoException {
        try {
            byte[] combined = Base64.getDecoder().decode(encryptedData);

            // Extract components
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            byte[] encrypted = new byte[combined.length - SALT_LENGTH - IV_LENGTH];

            System.arraycopy(combined, 0, salt, 0, SALT_LENGTH);
            System.arraycopy(combined, SALT_LENGTH, iv, 0, IV_LENGTH);
            System.arraycopy(combined, SALT_LENGTH + IV_LENGTH, encrypted, 0, encrypted.length);

            // Derive the same key
            String combinedKey = masterKey + userPassword;
            SecretKeySpec derivedKey = keyDerivation.deriveKey(
                    combinedKey.getBytes(StandardCharsets.UTF_8),
                    salt,
                    iterations,
                    KEY_LENGTH
            );

            // Decrypt
            byte[] decryptedData = aesEncryption.decryptGCM(encrypted, derivedKey, iv);
            return new String(decryptedData, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    /**
     * Encrypts private keys with additional security layer
     */
    public String encryptPrivateKey(String privateKey, String userPassword, String additionalEntropy) throws CryptoException {
        String enhancedPassword = userPassword + additionalEntropy + System.currentTimeMillis();
        return encryptSensitiveData(privateKey, enhancedPassword);
    }

    /**
     * Decrypts private keys
     */
    public String decryptPrivateKey(String encryptedPrivateKey, String userPassword, String additionalEntropy, long timestamp) throws CryptoException {
        String enhancedPassword = userPassword + additionalEntropy + timestamp;
        return decryptSensitiveData(encryptedPrivateKey, enhancedPassword);
    }

    /**
     * Generates cryptographically secure random string
     */
    public String generateSecureRandomString(int length) {
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Generates secure salt for password hashing
     */
    public byte[] generateSalt() {
        byte[] salt = new byte[32];
        secureRandom.nextBytes(salt);
        return salt;
    }
}