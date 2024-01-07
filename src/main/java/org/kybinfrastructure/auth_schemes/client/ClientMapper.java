package org.kybinfrastructure.auth_schemes.client;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.apache.commons.codec.binary.Hex;
import org.kybinfrastructure.auth_schemes.client.ClientAuthorityEntity.AuthorityId;
import org.kybinfrastructure.auth_schemes.common.Authority;
import org.kybinfrastructure.auth_schemes.common.CryptoUtils;
import org.kybinfrastructure.auth_schemes.common.TimeUtils;
import org.springframework.stereotype.Component;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Component
final class ClientMapper {

  @NonNull
  private final TimeUtils timeUtils;

  ClientEntity toEntityForCreation(String plainSecretKey, Client dto) {
    ClientEntity entity = new ClientEntity();
    entity.setName(dto.getName());
    entity.setApiKey(UUID.randomUUID().toString());
    entity.setHashedApiSecret(toHashedSecretKey(plainSecretKey));
    entity.setAuthorities(
        Optional.ofNullable(dto.getAuthorities()).map(a -> a.stream().map(this::toEntity))
            .map(Stream::toList).orElse(getDefaultClientAuthorities()));
    entity.setModificationDate(timeUtils.now());
    entity.setCreationDate(timeUtils.now());
    return entity;
  }

  Client toDto(ClientEntity entity) {
    return new Client(entity.getId(), entity.getName(), entity.getApiKey(),
        entity.getHashedApiSecret(),
        entity.getAuthorities().stream().map(ClientMapper::toDto).toList(),
        entity.getModificationDate(), entity.getCreationDate());
  }

  private ClientAuthorityEntity toEntity(Authority dto) {
    return new ClientAuthorityEntity(new AuthorityId(null, dto.getName().toString()),
        timeUtils.now());
  }

  private List<ClientAuthorityEntity> getDefaultClientAuthorities() {
    ClientAuthorityEntity defaultAuthority = new ClientAuthorityEntity();
    defaultAuthority.setId(AuthorityId.builder().name(Authority.Name.BASIC.toString()).build());
    defaultAuthority.setCreationDate(timeUtils.now());

    return List.of(defaultAuthority);
  }

  private static String toHashedSecretKey(String plainSecretKey) {
    byte[] salt = CryptoUtils.generateSalt(16);
    byte[] secretKeyHash = CryptoUtils.hash(plainSecretKey, salt);
    byte[] concatenatedSaltAndHash = Arrays.copyOf(salt, salt.length + secretKeyHash.length);
    System.arraycopy(secretKeyHash, 0, concatenatedSaltAndHash, salt.length, secretKeyHash.length);
    return Hex.encodeHexString(concatenatedSaltAndHash);
  }

  private static Authority toDto(ClientAuthorityEntity entity) {
    return new Authority(Authority.Name.valueOf(entity.getId().getName()),
        entity.getCreationDate());
  }

}
