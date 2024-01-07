package org.kybinfrastructure.auth_schemes.rest;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.kybinfrastructure.auth_schemes.client.Client;
import org.kybinfrastructure.auth_schemes.client.ClientStorageAdapter;
import org.kybinfrastructure.auth_schemes.common.CryptoUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Component
@ConditionalOnProperty(value = "auth.scheme", havingValue = "apikey")
@Slf4j
final class ApiKeyFilter extends OncePerRequestFilter {

  private final ClientStorageAdapter clientStorageAdapter;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    String apiKey = request.getHeader("X-API-KEY");
    String clientSecret = request.getHeader("X-CLIENT-SECRET");
    if (apiKey == null || clientSecret == null) {
      filterChain.doFilter(request, response);
      return;
    }

    Optional<Client> client = clientStorageAdapter.getByApiKey(apiKey);
    if (client.isEmpty()) {
      throw new UsernameNotFoundException("No client exists with the given API key: " + apiKey);
    }

    if (!isClientSecretValid(client.get(), clientSecret)) {
      log.debug("Given client secret with the given API key {} is not valid!", apiKey);
      filterChain.doFilter(request, response);
      return;
    }

    var grantedAuthorities = client.get().getAuthorities().stream()
        .map(a -> new SimpleGrantedAuthority(a.getName().toString())).toList();
    UsernamePasswordAuthenticationToken authenticationToken =
        new UsernamePasswordAuthenticationToken(User.builder().username(client.get().getApiKey())
            .password(clientSecret).disabled(false).authorities(grantedAuthorities).build(), null,
            grantedAuthorities);
    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

    filterChain.doFilter(request, response);
  }

  @SuppressWarnings({"java:S112"})
  private boolean isClientSecretValid(Client client, String givenClientSecret) {
    try {
      byte[] salt = Arrays.copyOfRange(Hex.decodeHex(client.getHashedApiSecret()), 0, 16);
      byte[] secretHash = CryptoUtils.hash(givenClientSecret, salt);
      byte[] concatenatedSaltAndHash = Arrays.copyOf(salt, salt.length + secretHash.length);
      System.arraycopy(secretHash, 0, concatenatedSaltAndHash, salt.length, secretHash.length);
      String encodedGivenClientSecret = Hex.encodeHexString(concatenatedSaltAndHash);

      return encodedGivenClientSecret.equals(client.getHashedApiSecret());
    } catch (DecoderException e) {
      throw new RuntimeException("salt couldn't be extracted!");
    }
  }

}
