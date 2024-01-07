package org.kybinfrastructure.auth_schemes.client;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.StreamSupport;
import org.kybinfrastructure.auth_schemes.common.CryptoUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Component
public class ClientStorageAdapter {

  @NonNull
  private final ClientRepository clientRepository;
  @NonNull
  private final ClientAuthorityRepository authorityRepository;
  @NonNull
  private final ClientMapper mapper;

  @Transactional(readOnly = true)
  public List<Client> getAll() {
    return StreamSupport.stream(clientRepository.findAll().spliterator(), false).map(mapper::toDto)
        .toList();
  }

  @Transactional
  public ClientCredentials create(Client clientToCreate) {
    Objects.requireNonNull(clientToCreate, "clientToCreate cannot be null!");

    String plainSecretKey = CryptoUtils.generateSecretKey();
    ClientEntity clientEntityToCreate = mapper.toEntityForCreation(plainSecretKey, clientToCreate);
    ClientEntity createdClientEntity = clientRepository.save(clientEntityToCreate);

    List<ClientAuthorityEntity> authorityEntitiesToCreate = createdClientEntity.getAuthorities();
    authorityEntitiesToCreate.forEach(e -> e.getId().setClientId(createdClientEntity.getId()));
    authorityRepository.saveAll(authorityEntitiesToCreate);

    return new ClientCredentials(clientEntityToCreate.getApiKey(), plainSecretKey);
  }

  @Transactional(readOnly = true)
  public Optional<Client> getById(Long id) {
    Objects.requireNonNull(id, "id cannot be null!");
    return clientRepository.findById(id).map(mapper::toDto);
  }

  @Transactional(readOnly = true)
  public Optional<Client> getByApiKey(String apiKey) {
    Objects.requireNonNull(apiKey, "apiKey cannot be null!");
    return clientRepository.findByApiKey(apiKey).map(mapper::toDto);
  }

  @Transactional(readOnly = true)
  public Optional<Client> getByName(String name) {
    Objects.requireNonNull(name, "name cannot be null!");
    return clientRepository.findByName(name).map(mapper::toDto);
  }

}
