package org.kybinfrastructure.auth_schemes.rest;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import org.kybinfrastructure.auth_schemes.client.Client;
import org.kybinfrastructure.auth_schemes.client.ClientCredentials;
import org.kybinfrastructure.auth_schemes.client.ClientStorageAdapter;
import org.kybinfrastructure.auth_schemes.common.Authority;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
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

    var clientStorageAdapter = event.getApplicationContext().getBean(ClientStorageAdapter.class);
    if (clientStorageAdapter.getByName("ADMIN").isPresent()) {
      return;
    }

    Client adminClient = Client.builder().name("ADMIN")
        .authorities(Stream.of(Authority.Name.values()).map(n -> new Authority(n, null)).toList())
        .build();
    ClientCredentials adminCredentials = clientStorageAdapter.create(adminClient);
    log.info("Admin client was created: {}", adminCredentials);

    IS_ADMIN_CREATED.set(true);
  }

}
