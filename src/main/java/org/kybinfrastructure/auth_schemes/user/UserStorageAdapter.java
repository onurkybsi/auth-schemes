package org.kybinfrastructure.auth_schemes.user;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.StreamSupport;
import org.apache.commons.codec.binary.Hex;
import org.kybinfrastructure.auth_schemes.CryptoUtils;
import org.kybinfrastructure.auth_schemes.TimeUtils;
import org.kybinfrastructure.auth_schemes.common.Authority;
import org.kybinfrastructure.auth_schemes.user.UserAuthorityEntity.AuthorityId;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Component
public class UserStorageAdapter {

  @NonNull
  private final UserRepository userRepository;
  @NonNull
  private final UserAuthorityRepository authorityRepository;
  @NonNull
  private final TimeUtils timeUtils;

  @Transactional(readOnly = true)
  public List<User> getAll() {
    return StreamSupport.stream(userRepository.findAll().spliterator(), false)
        .map(UserStorageAdapter::toDto).toList();
  }

  @Transactional
  public User create(User userToCreate) {
    UserEntity userEntityToCreate = toEntityForCreation(userToCreate);
    UserEntity createdUserEntity = userRepository.save(userEntityToCreate);

    List<UserAuthorityEntity> authorityEntitiesToCreate = createdUserEntity.getAuthorities();
    authorityEntitiesToCreate.forEach(e -> e.getId().setUserId(createdUserEntity.getId()));
    authorityRepository.saveAll(authorityEntitiesToCreate);

    return toDto(createdUserEntity);
  }

  @Transactional(readOnly = true)
  public Optional<User> get(Long id) {
    return userRepository.findById(id).map(UserStorageAdapter::toDto);
  }

  @Transactional(readOnly = true)
  public Optional<User> get(String email) {
    return userRepository.findByEmail(email).map(UserStorageAdapter::toDto);
  }

  private UserEntity toEntityForCreation(User dto) {
    byte[] salt = CryptoUtils.generateSalt(16);
    byte[] passwordHash = CryptoUtils.hash(dto.getPassword(), salt);
    byte[] concatenatedSaltAndHash = Arrays.copyOf(salt, salt.length + passwordHash.length);
    System.arraycopy(passwordHash, 0, concatenatedSaltAndHash, salt.length, passwordHash.length);
    String hashedPassword = Hex.encodeHexString(concatenatedSaltAndHash);

    UserEntity entity = new UserEntity();
    entity.setFirstName(dto.getFirstName());
    entity.setLastName(dto.getLastName());
    entity.setEmail(dto.getEmail());
    entity.setHashedPassword(hashedPassword);
    entity.setAuthorities(List.of(UserAuthorityEntity.builder()
        .id(AuthorityId.builder().name(Authority.Name.BASIC.toString()).build())
        .creationDate(timeUtils.now()).build()));
    entity.setModificationDate(timeUtils.now());
    entity.setCreationDate(timeUtils.now());

    return entity;
  }

  private static User toDto(UserEntity entity) {
    return new User(entity.getId(), entity.getFirstName(), entity.getLastName(), entity.getEmail(),
        entity.getHashedPassword(),
        entity.getAuthorities().stream().map(UserStorageAdapter::toDto).toList(),
        entity.getModificationDate(), entity.getCreationDate());
  }

  private static Authority toDto(UserAuthorityEntity entity) {
    return new Authority(Authority.Name.valueOf(entity.getId().getName()),
        entity.getCreationDate());
  }

}
