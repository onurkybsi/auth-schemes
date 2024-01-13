package org.kybinfrastructure.auth_schemes.rest.security;

import java.io.IOException;
import java.util.Collection;
import org.kybinfrastructure.auth_schemes.user.UserStorageAdapter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@ConditionalOnProperty(value = "auth.scheme", havingValue = "token")
final class JwtTokenFilter extends OncePerRequestFilter {

  private final JwtParser parser;
  private final UserStorageAdapter userStorageAdapter;

  public JwtTokenFilter(@NonNull @Value("${auth.jwtSecret}") String jwtSecret,
      UserStorageAdapter userStorageAdapter) {
    this.parser = Jwts.parser().verifyWith(Keys.hmacShaKeyFor(jwtSecret.getBytes())).build();
    this.userStorageAdapter = userStorageAdapter;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    String header = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (header == null || !header.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }

    String jwtTokenRaw = header.split(" ")[1].trim();
    Jws<Claims> jwtToken = deserializeJwtToken(jwtTokenRaw);
    if (jwtToken == null) {
      log.debug("JWT token couldn't be validated: {}", jwtTokenRaw);
      filterChain.doFilter(request, response);
      return;
    }

    var authenticatedUser =
        userStorageAdapter.get(jwtToken.getPayload().get("id", Long.class)).orElseThrow();

    var grantedAuthorities = authenticatedUser.getAuthorities().stream()
        .map(a -> new SimpleGrantedAuthority(a.getName().toString())).toList();
    SecurityContextHolder.getContext().setAuthentication(
        new JwtAuthenticationToken(authenticatedUser.getId(), grantedAuthorities));

    filterChain.doFilter(request, response);
  }

  private Jws<Claims> deserializeJwtToken(String jwtTokenRaw) {
    try {
      return parser.parseSignedClaims(jwtTokenRaw);
    } catch (JwtException e) {
      return null;
    }
  }

  static class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Long userId;

    public JwtAuthenticationToken(Long userId, Collection<? extends GrantedAuthority> authorities) {
      super(authorities);
      this.userId = userId;
    }

    @Override
    public Object getCredentials() {
      return null;
    }

    @Override
    public Object getPrincipal() {
      return userId;
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = super.hashCode();
      result = prime * result + ((userId == null) ? 0 : userId.hashCode());
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj)
        return true;
      if (!super.equals(obj))
        return false;
      if (getClass() != obj.getClass())
        return false;
      JwtAuthenticationToken other = (JwtAuthenticationToken) obj;
      if (userId == null) {
        if (other.userId != null)
          return false;
      } else if (!userId.equals(other.userId))
        return false;
      return true;
    }

  }

}
