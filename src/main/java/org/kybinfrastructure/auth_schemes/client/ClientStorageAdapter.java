package org.kybinfrastructure.auth_schemes.client;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.StreamSupport;
import org.apache.commons.codec.binary.Hex;
import org.kybinfrastructure.auth_schemes.CryptoUtils;
import org.kybinfrastructure.auth_schemes.TimeUtils;
import org.kybinfrastructure.auth_schemes.client.ClientAuthorityEntity.AuthorityId;
import org.kybinfrastructure.auth_schemes.common.Authority;
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
  private final TimeUtils timeUtils;

  @Transactional(readOnly = true)
  public List<Client> getAll() {
    return StreamSupport.stream(clientRepository.findAll().spliterator(), false)
        .map(ClientStorageAdapter::toDto).toList();
  }

  @Transactional
  public ClientCredentials create(Client clientToCreate) {
    String secretKey = CryptoUtils.generateSecretKey();
    ClientEntity clientEntityToCreate = toEntityForCreation(secretKey, clientToCreate);
    ClientEntity createdClientEntity = clientRepository.save(clientEntityToCreate);

    List<ClientAuthorityEntity> authorityEntitiesToCreate = createdClientEntity.getAuthorities();
    authorityEntitiesToCreate.forEach(e -> e.getId().setClientId(createdClientEntity.getId()));
    authorityRepository.saveAll(authorityEntitiesToCreate);

    return new ClientCredentials(clientEntityToCreate.getApiKey(), secretKey);
  }

  @Transactional(readOnly = true)
  public Optional<Client> get(Long id) {
    return clientRepository.findById(id).map(ClientStorageAdapter::toDto);
  }

  @Transactional(readOnly = true)
  public Optional<Client> get(String apiKey) {
    return clientRepository.findByApiKey(apiKey).map(ClientStorageAdapter::toDto);
  }

  private ClientEntity toEntityForCreation(String secretKey, Client dto) {
    byte[] salt = CryptoUtils.generateSalt(16);
    byte[] secretKeyHash = CryptoUtils.hash(secretKey, salt);
    byte[] concatenatedSaltAndHash = Arrays.copyOf(salt, salt.length + secretKeyHash.length);
    System.arraycopy(secretKeyHash, 0, concatenatedSaltAndHash, salt.length, secretKeyHash.length);
    String hashedSecretKey = Hex.encodeHexString(concatenatedSaltAndHash);

    ClientEntity entity = new ClientEntity();
    entity.setName(dto.getName());
    entity.setApiKey(UUID.randomUUID().toString());
    entity.setHashedApiSecret(hashedSecretKey);
    entity.setAuthorities(List.of(ClientAuthorityEntity.builder()
        .id(AuthorityId.builder().name(Authority.Name.BASIC.toString()).build())
        .creationDate(timeUtils.now()).build()));
    entity.setModificationDate(timeUtils.now());
    entity.setCreationDate(timeUtils.now());
    return entity;
  }

  private static Client toDto(ClientEntity entity) {
    return new Client(entity.getId(), entity.getName(), entity.getApiKey(),
        entity.getHashedApiSecret(),
        entity.getAuthorities().stream().map(ClientStorageAdapter::toDto).toList(),
        entity.getModificationDate(), entity.getCreationDate());
  }

  private static Authority toDto(ClientAuthorityEntity entity) {
    return new Authority(Authority.Name.valueOf(entity.getId().getName()),
        entity.getCreationDate());
  }

}
