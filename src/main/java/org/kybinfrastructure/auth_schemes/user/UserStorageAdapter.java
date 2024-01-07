package org.kybinfrastructure.auth_schemes.user;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.StreamSupport;
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
  private final UserMapper mapper;

  @Transactional(readOnly = true)
  public List<User> getAll() {
    return StreamSupport.stream(userRepository.findAll().spliterator(), false).map(mapper::toDto)
        .toList();
  }

  @Transactional
  public User create(User userToCreate) {
    Objects.requireNonNull(userToCreate, "userToCreate cannot be null!");

    UserEntity userEntityToCreate = mapper.toEntityForCreation(userToCreate);
    UserEntity createdUserEntity = userRepository.save(userEntityToCreate);

    List<UserAuthorityEntity> authorityEntitiesToCreate = createdUserEntity.getAuthorities();
    authorityEntitiesToCreate.forEach(e -> e.getId().setUserId(createdUserEntity.getId()));
    authorityRepository.saveAll(authorityEntitiesToCreate);

    return mapper.toDto(createdUserEntity);
  }

  @Transactional(readOnly = true)
  public Optional<User> get(Long id) {
    Objects.requireNonNull(id, "id cannot be null!");
    return userRepository.findById(id).map(mapper::toDto);
  }

  @Transactional(readOnly = true)
  public Optional<User> get(String email) {
    Objects.requireNonNull(email, "email cannot be null!");
    return userRepository.findByEmail(email).map(mapper::toDto);
  }

}
