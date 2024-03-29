package org.kybinfrastructure.auth_schemes.rest.security;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.kybinfrastructure.auth_schemes.client.Client;
import org.kybinfrastructure.auth_schemes.client.ClientStorageAdapter;
import org.kybinfrastructure.auth_schemes.common.util.CryptoUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
@Component
@ConditionalOnProperty(value = "auth.scheme", havingValue = "apikey")
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
    SecurityContextHolder.getContext()
        .setAuthentication(new ApiKeyAuthentication(apiKey, grantedAuthorities, true));

    filterChain.doFilter(request, response);
  }

  @SuppressWarnings({"java:S112"})
  private boolean isClientSecretValid(Client client, String givenClientSecret) {
    try {
      byte[] salt = Arrays.copyOfRange(Hex.decodeHex(client.getHashedClientSecret()), 0, 16);
      byte[] givenSecretHash = CryptoUtils.hash(givenClientSecret, salt);
      byte[] concatenatedSaltAndHash = Arrays.copyOf(salt, salt.length + givenSecretHash.length);
      System.arraycopy(givenSecretHash, 0, concatenatedSaltAndHash, salt.length,
          givenSecretHash.length);
      String encodedGivenClientSecretHash = Hex.encodeHexString(concatenatedSaltAndHash);

      return encodedGivenClientSecretHash.equals(client.getHashedClientSecret());
    } catch (DecoderException e) {
      throw new RuntimeException("salt couldn't be extracted!");
    }
  }

  @RequiredArgsConstructor(access = AccessLevel.PACKAGE)
  @AllArgsConstructor(access = AccessLevel.PACKAGE)
  static class ApiKeyAuthentication implements Authentication {

    private final String apiKey;
    private final Collection<? extends GrantedAuthority> authorities;

    private boolean isAuthenticated;

    @Override
    public String getName() {
      return this.getPrincipal() != null ? this.getPrincipal().toString() : null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
      return authorities;
    }

    @Override
    public Object getCredentials() {
      return null;
    }

    @Override
    public Object getDetails() {
      return null;
    }

    @Override
    public Object getPrincipal() {
      return apiKey;
    }

    @Override
    public boolean isAuthenticated() {
      return isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
      this.isAuthenticated = isAuthenticated;
    }

  }

}
