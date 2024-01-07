package org.kybinfrastructure.auth_schemes.common.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class CryptoUtils {

  private static final String HASHING_ALGORITHM = "PBKDF2WithHmacSHA512";
  private static final int HASHING_ITERATION_COUNT = 100000;
  private static final int HASHING_KEY_LENGTH = 512;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private CryptoUtils() {
    throw new UnsupportedOperationException("This class is not initiable!");
  }

  public static byte[] hash(final String value, final byte[] salt) {
    Objects.requireNonNull(value, "value cannot be null!");
    Objects.requireNonNull(salt, "salt cannot be null!");

    PBEKeySpec spec =
        new PBEKeySpec(value.toCharArray(), salt, HASHING_ITERATION_COUNT, HASHING_KEY_LENGTH);

    try {
      SecretKeyFactory factory = SecretKeyFactory.getInstance(HASHING_ALGORITHM);
      return factory.generateSecret(spec).getEncoded();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException("Value couldn't be hashed!"); // NOSONAR
    } finally {
      spec.clearPassword();
    }
  }

  public static byte[] generateSalt(final int length) {
    if (length <= 0) {
      throw new IllegalArgumentException("length cannot be less than 0!");
    }

    byte[] salt = new byte[length];
    SECURE_RANDOM.nextBytes(salt);
    return salt;
  }

  public static String generateSecretKey() {
    try {
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(256);
      return Base64.getEncoder().encodeToString(keyGenerator.generateKey().getEncoded());
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Secret key couldn't be generated!"); // NOSONAR
    }
  }

}
