package org.kybinfrastructure.auth_schemes.client;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
interface ClientAuthorityRepository extends CrudRepository<ClientAuthorityEntity, Long> {
}
