package com.zerotrace.crypto;

import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.digests.SHA512Digest;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Advanced key derivation using multiple algorithms for maximum security
 */
public class KeyDerivation {

    private static final String ALGORITHM = "AES";
    private static final int DEFAULT_KEY_LENGTH = 256; // bits

    // PBKDF2 parameters
    private static final int DEFAULT_PBKDF2_ITERATIONS = 1_000_000;

    // Scrypt parameters (memory-hard)
    private static final int SCRYPT_N = 32768; // CPU/memory cost
    private static final int SCRYPT_R = 8;     // block size
    private static final int SCRYPT_P = 1;     // parallelization

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Derives key using PBKDF2 with SHA-512
     */
    public SecretKeySpec deriveKey(byte[] password, byte[] salt, int iterations, int keyLengthBits) {
        try {
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA512Digest());
            generator.init(password, salt, iterations);

            KeyParameter keyParam = (KeyParameter) generator.generateDerivedParameters(keyLengthBits);
            return new SecretKeySpec(keyParam.getKey(), ALGORITHM);

        } catch (Exception e) {
            throw new RuntimeException("Key derivation failed", e);
        }
    }

    /**
     * Derives key using Scrypt (memory-hard function)
     */
    public SecretKeySpec deriveKeyScrypt(String password, byte[] salt, int keyLengthBytes) {
        try {
            byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
            byte[] derivedKey = SCrypt.generate(passwordBytes, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, keyLengthBytes);
            return new SecretKeySpec(derivedKey, ALGORITHM);

        } catch (Exception e) {
            throw new RuntimeException("Scrypt key derivation failed", e);
        }
    }

    /**
     * Enhanced key derivation combining PBKDF2 and Scrypt
     */
    public SecretKeySpec deriveEnhancedKey(String password, byte[] salt, int iterations) {
        try {
            // First pass with PBKDF2
            byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec pbkdf2Key = deriveKey(passwordBytes, salt, iterations, DEFAULT_KEY_LENGTH);

            // Second pass with Scrypt using PBKDF2 result
            byte[] scryptKey = SCrypt.generate(pbkdf2Key.getEncoded(), salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, 32);

            // Combine both results with XOR for enhanced security
            byte[] pbkdf2Bytes = pbkdf2Key.getEncoded();
            byte[] finalKey = new byte[32];

            for (int i = 0; i < 32; i++) {
                finalKey[i] = (byte) (pbkdf2Bytes[i] ^ scryptKey[i]);
            }

            return new SecretKeySpec(finalKey, ALGORITHM);

        } catch (Exception e) {
            throw new RuntimeException("Enhanced key derivation failed", e);
        }
    }

    /**
     * Derives key with additional entropy from system state
     */
    public SecretKeySpec deriveKeyWithEntropy(String password, byte[] salt, String additionalEntropy) {
        try {
            // Combine password with additional entropy
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            digest.update(password.getBytes(StandardCharsets.UTF_8));
            digest.update(additionalEntropy.getBytes(StandardCharsets.UTF_8));
            digest.update(String.valueOf(System.nanoTime()).getBytes());

            byte[] enhancedPassword = digest.digest();

            return deriveEnhancedKey(new String(enhancedPassword, StandardCharsets.UTF_8), salt, DEFAULT_PBKDF2_ITERATIONS);

        } catch (Exception e) {
            throw new RuntimeException("Entropy-enhanced key derivation failed", e);
        }
    }

    /**
     * Generates cryptographically secure salt
     */
    public byte[] generateSalt(int lengthBytes) {
        byte[] salt = new byte[lengthBytes];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Key stretching function to slow down brute force attacks
     */
    public byte[] stretchKey(byte[] key, int iterations) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] stretched = key.clone();

            for (int i = 0; i < iterations; i++) {
                digest.reset();
                digest.update(stretched);
                digest.update(String.valueOf(i).getBytes());
                stretched = digest.digest();
            }

            return stretched;
        } catch (Exception e) {
            throw new RuntimeException("Key stretching failed", e);
        }
    }
}