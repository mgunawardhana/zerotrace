package com.zerotrace.crypto;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Military-grade AES-256-GCM encryption implementation
 * Uses Bouncy Castle for enhanced security and performance
 */
public class AESEncryption {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96 bits recommended for GCM
    private static final int GCM_TAG_LENGTH = 16; // 128 bits authentication tag

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Encrypts data using AES-256-GCM with Bouncy Castle for maximum security
     */
    public byte[] encryptGCM(byte[] plaintext, SecretKeySpec key, byte[] iv) throws Exception {
        // Use Bouncy Castle's GCM implementation for enhanced security
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());

        AEADParameters parameters = new AEADParameters(
                new KeyParameter(key.getEncoded()),
                GCM_TAG_LENGTH * 8, // tag length in bits
                iv,
                null // no additional authenticated data
        );

        cipher.init(true, parameters);

        byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.length)];
        int outputLen = cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
        outputLen += cipher.doFinal(ciphertext, outputLen);

        // Return only the needed bytes
        byte[] result = new byte[outputLen];
        System.arraycopy(ciphertext, 0, result, 0, outputLen);

        return result;
    }

    /**
     * Decrypts data using AES-256-GCM with Bouncy Castle
     */
    public byte[] decryptGCM(byte[] ciphertext, SecretKeySpec key, byte[] iv) throws Exception {
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());

        AEADParameters parameters = new AEADParameters(
                new KeyParameter(key.getEncoded()),
                GCM_TAG_LENGTH * 8,
                iv,
                null
        );

        cipher.init(false, parameters);

        byte[] plaintext = new byte[cipher.getOutputSize(ciphertext.length)];
        int outputLen = cipher.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);
        outputLen += cipher.doFinal(plaintext, outputLen);

        // Return only the needed bytes
        byte[] result = new byte[outputLen];
        System.arraycopy(plaintext, 0, result, 0, outputLen);

        return result;
    }

    /**
     * Alternative JCE implementation for compatibility
     */
    public byte[] encryptJCE(byte[] plaintext, SecretKeySpec key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(plaintext);
    }

    /**
     * Alternative JCE decryption for compatibility
     */
    public byte[] decryptJCE(byte[] ciphertext, SecretKeySpec key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(ciphertext);
    }

    /**
     * Generates cryptographically secure random IV
     */
    public byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Constant-time comparison to prevent timing attacks
     */
    public boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }

        return result == 0;
    }
}