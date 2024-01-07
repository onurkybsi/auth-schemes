package org.kybinfrastructure.auth_schemes.rest.security;

import java.io.IOException;
import javax.crypto.SecretKey;
import org.kybinfrastructure.auth_schemes.user.UserStorageAdapter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
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

  private final SecretKey jwtSecret;
  private final UserStorageAdapter userStorageAdapter;

  public JwtTokenFilter(@NonNull @Value("${auth.jwtSecret}") String jwtSecret,
      UserStorageAdapter userStorageAdapter) {
    this.jwtSecret = Keys.hmacShaKeyFor(jwtSecret.getBytes());
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
    UsernamePasswordAuthenticationToken authenticationToken =
        new UsernamePasswordAuthenticationToken(User.builder()
            .username(authenticatedUser.getEmail()).password(authenticatedUser.getPassword())
            .disabled(false).authorities(grantedAuthorities).build(), null, grantedAuthorities);
    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

    filterChain.doFilter(request, response);
  }

  private Jws<Claims> deserializeJwtToken(String jwtTokenRaw) {
    try {
      return Jwts.parser().verifyWith(jwtSecret).build().parseSignedClaims(jwtTokenRaw);
    } catch (JwtException e) {
      return null;
    }
  }

}
