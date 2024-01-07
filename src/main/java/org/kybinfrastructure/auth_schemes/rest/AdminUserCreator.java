package org.kybinfrastructure.auth_schemes.rest;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import org.kybinfrastructure.auth_schemes.client.Client;
import org.kybinfrastructure.auth_schemes.client.ClientCredentials;
import org.kybinfrastructure.auth_schemes.client.ClientStorageAdapter;
import org.kybinfrastructure.auth_schemes.common.dto.Authority;
import org.kybinfrastructure.auth_schemes.user.User;
import org.kybinfrastructure.auth_schemes.user.UserStorageAdapter;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
final class AdminUserCreator implements ApplicationListener<ContextRefreshedEvent> {

  private static final AtomicBoolean IS_ADMIN_CREATED = new AtomicBoolean(false);

  @Override
  public void onApplicationEvent(ContextRefreshedEvent event) {
    if (IS_ADMIN_CREATED.get()) {
      return;
    }

    Environment env = event.getApplicationContext().getEnvironment();
    String authScheme = env.getProperty("auth.scheme");

    if ("apikey".equals(authScheme)) {
      var clientStorageAdapter = event.getApplicationContext().getBean(ClientStorageAdapter.class);
      if (clientStorageAdapter.getByName("ADMIN").isPresent()) {
        return;
      }

      Client adminClient = Client.builder().name("ADMIN")
          .authorities(Stream.of(Authority.Name.values()).map(n -> new Authority(n, null)).toList())
          .build();
      ClientCredentials adminCredentials = clientStorageAdapter.create(adminClient);
      log.info("Admin client was created: {}", adminCredentials);
    } else {
      var userStorageAdapter = event.getApplicationContext().getBean(UserStorageAdapter.class);
      if (userStorageAdapter.get("o.kayabasi@outlook.com").isPresent()) {
        return;
      }

      String adminFirstName = env.getProperty("auth.adminUser.firstName");
      String adminLastName = env.getProperty("auth.adminUser.lastName");
      String adminEmail = env.getProperty("auth.adminUser.email");
      User adminUserToCreate = User.builder().firstName(adminFirstName).lastName(adminLastName)
          .email(adminEmail).password(generateStrongPassword())
          .authorities(Stream.of(Authority.Name.values()).map(n -> new Authority(n, null)).toList())
          .build();
      User createdAdminUser = userStorageAdapter.create(adminUserToCreate);
      log.info("Admin user was created with the email {} and the password: {}",
          createdAdminUser.getEmail(), createdAdminUser.getPassword());
    }

    IS_ADMIN_CREATED.set(true);
  }

  private static String generateStrongPassword() {
    // TODO: Implement however you want...
    return "Strongpassword123!";
  }

}
