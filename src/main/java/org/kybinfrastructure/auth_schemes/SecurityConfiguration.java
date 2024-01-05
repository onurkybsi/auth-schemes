package org.kybinfrastructure.auth_schemes;

import java.util.Arrays;
import java.util.stream.Stream;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.kybinfrastructure.auth_schemes.common.Authority;
import org.kybinfrastructure.auth_schemes.user.UserStorageAdapter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfiguration {

  @Bean
  @ConditionalOnProperty(value = "auth.scheme", havingValue = "basic")
  public SecurityFilterChain securityFilterChainForBasicAuth(HttpSecurity httpSecurity)
      throws Exception {
    return httpSecurity
        .authorizeHttpRequests(c -> c.requestMatchers(HttpMethod.GET, "/users/**")
            .hasAnyAuthority(Stream.of(Authority.Name.values()).map(Authority.Name::toString)
                .toArray(String[]::new))
            .requestMatchers(HttpMethod.POST, "/users").permitAll())
        .httpBasic(Customizer.withDefaults()).csrf(c -> c.disable())
        .sessionManagement(c -> c.disable()).build();
  }

  @Bean
  @ConditionalOnProperty(value = "auth.scheme", havingValue = "token")
  public SecurityFilterChain securityFilterChainForTokenBased(HttpSecurity httpSecurity,
      JwtTokenFilter jwtTokenFilter) throws Exception {
    return httpSecurity
        .authorizeHttpRequests(c -> c.requestMatchers(HttpMethod.GET, "/users/**")
            .hasAnyAuthority(Stream.of(Authority.Name.values()).map(Authority.Name::toString)
                .toArray(String[]::new))
            .requestMatchers(HttpMethod.POST, "/users").permitAll().requestMatchers("/jwt")
            .permitAll())
        .csrf(c -> c.disable()).sessionManagement(c -> c.disable())
        .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class).build();
  }

  @Bean
  @ConditionalOnProperty(value = "auth.scheme", havingValue = "apikey")
  public SecurityFilterChain securityFilterChainForApiKey(HttpSecurity httpSecurity,
      ApiKeyFilter apiKeyFilter) throws Exception {
    return httpSecurity
        .authorizeHttpRequests(c -> c.requestMatchers(HttpMethod.GET, "/clients/**")
            .hasAnyAuthority(Stream.of(Authority.Name.values()).map(Authority.Name::toString)
                .toArray(String[]::new))
            .requestMatchers(HttpMethod.POST, "/clients").permitAll())
        .csrf(c -> c.disable()).sessionManagement(c -> c.disable())
        .addFilterBefore(apiKeyFilter, UsernamePasswordAuthenticationFilter.class).build();
  }

  @Bean
  public UserDetailsService userDetailsService(UserStorageAdapter userStorageAdapter) {
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
  public PasswordEncoder passwordEncoder() {
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
  public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
      PasswordEncoder passwordEncoder) {
    DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
    authenticationProvider.setUserDetailsService(userDetailsService);
    authenticationProvider.setPasswordEncoder(passwordEncoder);

    ProviderManager providerManager = new ProviderManager(authenticationProvider);
    providerManager.setEraseCredentialsAfterAuthentication(false);

    return providerManager;
  }

}
