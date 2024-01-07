package org.kybinfrastructure.auth_schemes.jwt;

import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import javax.crypto.SecretKey;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.kybinfrastructure.auth_schemes.common.CryptoUtils;
import org.kybinfrastructure.auth_schemes.common.TimeUtils;
import org.kybinfrastructure.auth_schemes.user.User;
import org.kybinfrastructure.auth_schemes.user.UserStorageAdapter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.NonNull;

@Component
public final class JwtAuthAdapter {

  private static final String ISSUER = "auth-schemes";

  private final UserStorageAdapter userStorageAdapter;
  private final SecretKey jwtSecret;
  private final TimeUtils timeUtils;

  public JwtAuthAdapter(@NonNull UserStorageAdapter userStorageAdapter,
      @NonNull @Value("${auth.jwt.secret}") String jwtSecret, TimeUtils timeUtils) {
    this.userStorageAdapter = userStorageAdapter;
    this.jwtSecret = Keys.hmacShaKeyFor(jwtSecret.getBytes());
    this.timeUtils = timeUtils;
  }

  public String generateToken(Authentication authentication) {
    Objects.requireNonNull(authentication, "authentication cannot be null!");

    User user = userStorageAdapter.get(authentication.getEmail()).orElseThrow(
        () -> new RuntimeException("No user exists by given email: " + authentication.getEmail()));
    assertPassword(user, authentication.getPassword());

    return Jwts.builder().issuer(ISSUER).claims(Map.of("id", user.getId()))
        .issuedAt(Date.from(timeUtils.instant()))
        .expiration(Date.from(timeUtils.instant().plus(5, ChronoUnit.MINUTES))).signWith(jwtSecret)
        .compact();
  }

  @SuppressWarnings({"java:S112"})
  private void assertPassword(User user, String rawPassword) {
    try {
      byte[] salt = Arrays.copyOfRange(Hex.decodeHex(user.getPassword()), 0, 16);
      byte[] passwordHash = CryptoUtils.hash(rawPassword, salt);
      byte[] concatenatedSaltAndHash = Arrays.copyOf(salt, salt.length + passwordHash.length);
      System.arraycopy(passwordHash, 0, concatenatedSaltAndHash, salt.length, passwordHash.length);
      String encodedRawPassword = Hex.encodeHexString(concatenatedSaltAndHash);

      if (!encodedRawPassword.equals(user.getPassword())) {
        throw new RuntimeException("Wrong password!");
      }
    } catch (DecoderException e) {
      throw new RuntimeException("salt couldn't be extracted!");
    }
  }

}
