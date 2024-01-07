package org.kybinfrastructure.auth_schemes.rest;

import java.util.List;
import org.kybinfrastructure.auth_schemes.client.Client;
import org.kybinfrastructure.auth_schemes.client.ClientCredentials;
import org.kybinfrastructure.auth_schemes.client.ClientStorageAdapter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@RestController
@RequestMapping("/clients")
class ClientRestController {

  @NonNull
  private final ClientStorageAdapter clientStorageAdapter;

  @GetMapping(produces = {"application/json"})
  @PreAuthorize("hasAuthority('GET_ALL_CLIENTS')")
  public ResponseEntity<List<Client>> getAll() {
    return ResponseEntity.ok(clientStorageAdapter.getAll());
  }

  @PostMapping(consumes = {"application/json"}, produces = {"application/json"})
  public ResponseEntity<ClientCredentials> create(@RequestBody @Valid Client userToCreate) {
    return new ResponseEntity<>(clientStorageAdapter.create(userToCreate), HttpStatus.CREATED);
  }

  @GetMapping(value = "/{id}", produces = {"application/json"})
  @PostAuthorize("returnObject.body.apiKey == authentication.principal.username or hasAuthority('GET_ALL_CLIENTS')")
  public ResponseEntity<Client> get(@PathVariable("id") Long id) {
    return clientStorageAdapter.getById(id).map(ResponseEntity::ok)
        .orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
  }

}
