package org.kybinfrastructure.auth_schemes.client;

import java.util.Optional;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
interface ClientRepository extends CrudRepository<ClientEntity, Long> {

  Optional<ClientEntity> findByApiKey(String apiKey);

}
