package org.kybinfrastructure.auth_schemes.user;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
interface UserAuthorityRepository extends CrudRepository<UserAuthorityEntity, Long> {
}
