package org.kybinfrastructure.auth_schemes.rest;

import java.util.Arrays;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.kybinfrastructure.auth_schemes.common.dto.Authority;
import org.kybinfrastructure.auth_schemes.common.util.CryptoUtils;
import org.kybinfrastructure.auth_schemes.user.UserStorageAdapter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfiguration {

  @Bean
  public SecurityFilterChain securityFilterChainForTokenBased(HttpSecurity httpSecurity,
      @Value("${auth.scheme:basic}") String authScheme, @Nullable ApiKeyFilter apiKeyFilter,
      @Nullable JwtTokenFilter jwtTokenFilter) throws Exception {
    if ("token".equals(authScheme)) {
      return configureDefaults(httpSecurity)
          .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class).build();
    } else if ("apikey".equals(authScheme)) {
      return configureDefaults(httpSecurity)
          .addFilterBefore(apiKeyFilter, UsernamePasswordAuthenticationFilter.class).build();
    }
    return configureDefaults(httpSecurity).httpBasic(Customizer.withDefaults()).build();
  }

  @Bean
  UserDetailsService userDetailsService(UserStorageAdapter userStorageAdapter) {
    return new UserDetailsService() {
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userStorageAdapter.get(username)
            .map(u -> User.builder().username(u.getEmail()).password(u.getPassword())
                .disabled(false)
                .authorities(u.getAuthorities().stream()
                    .map(a -> new SimpleGrantedAuthority(a.getName().toString())).toList())
                .build())
            .orElseThrow(() -> new UsernameNotFoundException(username));
      }
    };
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return new PasswordEncoder() {

      @Override
      public String encode(CharSequence rawPassword) {
        byte[] salt = CryptoUtils.generateSalt(16);
        byte[] passwordHash = CryptoUtils.hash(rawPassword.toString(), salt);
        byte[] concatenatedSaltAndHash = Arrays.copyOf(salt, salt.length + passwordHash.length);
        System.arraycopy(passwordHash, 0, concatenatedSaltAndHash, salt.length,
            passwordHash.length);
        return Hex.encodeHexString(concatenatedSaltAndHash);
      }

      @Override
      public boolean matches(CharSequence rawPassword, String encodedPassword) {
        try {
          byte[] salt = Arrays.copyOfRange(Hex.decodeHex(encodedPassword), 0, 16);
          byte[] passwordHash = CryptoUtils.hash(rawPassword.toString(), salt);
          byte[] concatenatedSaltAndHash = Arrays.copyOf(salt, salt.length + passwordHash.length);
          System.arraycopy(passwordHash, 0, concatenatedSaltAndHash, salt.length,
              passwordHash.length);
          String encodedRawPassword = Hex.encodeHexString(concatenatedSaltAndHash);

          return encodedRawPassword.equals(encodedPassword);
        } catch (DecoderException e) {
          throw new RuntimeException("salt couldn't be extracted!"); // NOSONAR
        }
      }

    };
  }

  @Bean
  AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
      PasswordEncoder passwordEncoder) {
    DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
    authenticationProvider.setUserDetailsService(userDetailsService);
    authenticationProvider.setPasswordEncoder(passwordEncoder);

    ProviderManager providerManager = new ProviderManager(authenticationProvider);
    providerManager.setEraseCredentialsAfterAuthentication(false);

    return providerManager;
  }

  private static HttpSecurity configureDefaults(HttpSecurity httpSecurity) throws Exception {
    AntPathRequestMatcher clientsGetEndpointsMatcher =
        new AntPathRequestMatcher("/clients/**", HttpMethod.GET.toString());
    AntPathRequestMatcher createClientEndpointMatcher =
        new AntPathRequestMatcher("/clients", HttpMethod.POST.toString());
    AntPathRequestMatcher usersGetEndpointsMatcher =
        new AntPathRequestMatcher("/users/**", HttpMethod.GET.toString());
    AntPathRequestMatcher createUserEndpointMatcher =
        new AntPathRequestMatcher("/users", HttpMethod.POST.toString());
    AntPathRequestMatcher createJwtTokenEndpointMatcher =
        new AntPathRequestMatcher("/jwt", HttpMethod.POST.toString());

    return httpSecurity.authorizeHttpRequests(c -> c.requestMatchers(clientsGetEndpointsMatcher)
        .hasAuthority(Authority.Name.BASIC.toString()).requestMatchers(createClientEndpointMatcher)
        .hasAuthority(Authority.Name.CREATE_CLIENT.toString())
        .requestMatchers(usersGetEndpointsMatcher).hasAuthority(Authority.Name.BASIC.toString())
        .requestMatchers(createUserEndpointMatcher).permitAll()
        .requestMatchers(createJwtTokenEndpointMatcher).permitAll()).csrf(c -> c.disable())
        .sessionManagement(c -> c.disable());
  }

}
