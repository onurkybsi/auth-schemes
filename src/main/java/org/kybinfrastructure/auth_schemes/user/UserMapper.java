package org.kybinfrastructure.auth_schemes.user;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.apache.commons.codec.binary.Hex;
import org.kybinfrastructure.auth_schemes.common.dto.Authority;
import org.kybinfrastructure.auth_schemes.common.util.CryptoUtils;
import org.kybinfrastructure.auth_schemes.common.util.TimeUtils;
import org.kybinfrastructure.auth_schemes.user.UserAuthorityEntity.AuthorityId;
import org.springframework.stereotype.Component;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Component
final class UserMapper {

  @NonNull
  private final TimeUtils timeUtils;

  UserEntity toEntityForCreation(User dto) {
    UserEntity entity = new UserEntity();
    entity.setFirstName(dto.getFirstName());
    entity.setLastName(dto.getLastName());
    entity.setEmail(dto.getEmail());
    entity.setHashedPassword(toHashedPassword(dto.getPassword()));
    entity.setAuthorities(
        Optional.ofNullable(dto.getAuthorities()).map(a -> a.stream().map(this::toEntity))
            .map(Stream::toList).orElse(getDefaultClientAuthorities()));
    entity.setModificationDate(timeUtils.now());
    entity.setCreationDate(timeUtils.now());
    return entity;
  }

  User toDto(UserEntity entity) {
    return new User(entity.getId(), entity.getFirstName(), entity.getLastName(), entity.getEmail(),
        entity.getHashedPassword(),
        entity.getAuthorities().stream().map(UserMapper::toDto).toList(),
        entity.getModificationDate(), entity.getCreationDate());
  }

  private UserAuthorityEntity toEntity(Authority dto) {
    return new UserAuthorityEntity(new AuthorityId(null, dto.getName().toString()),
        timeUtils.now());
  }

  private List<UserAuthorityEntity> getDefaultClientAuthorities() {
    UserAuthorityEntity defaultAuthority = new UserAuthorityEntity();
    defaultAuthority.setId(AuthorityId.builder().name(Authority.Name.BASIC.toString()).build());
    defaultAuthority.setCreationDate(timeUtils.now());

    return List.of(defaultAuthority);
  }

  private static String toHashedPassword(String plainPassword) {
    byte[] salt = CryptoUtils.generateSalt(16);
    byte[] passowordHash = CryptoUtils.hash(plainPassword, salt);
    byte[] concatenatedSaltAndHash = Arrays.copyOf(salt, salt.length + passowordHash.length);
    System.arraycopy(passowordHash, 0, concatenatedSaltAndHash, salt.length, passowordHash.length);
    return Hex.encodeHexString(concatenatedSaltAndHash);
  }

  private static Authority toDto(UserAuthorityEntity entity) {
    return new Authority(Authority.Name.valueOf(entity.getId().getName()),
        entity.getCreationDate());
  }

}
