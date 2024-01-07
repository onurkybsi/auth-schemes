package org.kybinfrastructure.auth_schemes.rest.controller;

import java.util.List;
import org.kybinfrastructure.auth_schemes.common.dto.Authority;
import org.kybinfrastructure.auth_schemes.user.User;
import org.kybinfrastructure.auth_schemes.user.UserStorageAdapter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
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
@RequestMapping("/users")
class UserRestController {

  @NonNull
  private final UserStorageAdapter userStorageAdapter;

  @GetMapping(produces = {"application/json"})
  @PreAuthorize("hasAuthority('GET_ALL_USERS')")
  public ResponseEntity<List<User>> getAll() {
    return ResponseEntity.ok(userStorageAdapter.getAll());
  }

  @PostMapping(consumes = {"application/json"}, produces = {"application/json"})
  public ResponseEntity<User> create(@RequestBody @Valid User userToCreate) {
    return new ResponseEntity<>(userStorageAdapter.create(userToCreate), HttpStatus.CREATED);
  }

  @GetMapping(value = "/{id}", produces = {"application/json"})
  @PostAuthorize("returnObject.statusCodeValue == 200 ? returnObject.body.email == authentication.principal.username or hasAuthority('GET_ALL_USERS') : true")
  public ResponseEntity<User> get(@PathVariable("id") Long id, Authentication authentication) {
    return userStorageAdapter.get(id).map(ResponseEntity::ok).orElseGet(() -> {
      if (authentication.getAuthorities().stream()
          .anyMatch(a -> Authority.Name.GET_ALL_USERS.toString().equals(a.getAuthority()))) {
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
      } else {
        return new ResponseEntity<>(HttpStatus.FORBIDDEN);
      }
    });
  }

}
