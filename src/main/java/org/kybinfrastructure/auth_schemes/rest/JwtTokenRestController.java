package org.kybinfrastructure.auth_schemes.rest;

import org.kybinfrastructure.auth_schemes.jwt.Authentication;
import org.kybinfrastructure.auth_schemes.jwt.JwtTokenAdapter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
@RequestMapping("/jwt")
final class JwtTokenRestController {

  @NonNull
  private final JwtTokenAdapter jwtAuthAdapter;

  @PostMapping(consumes = {"application/json"}, produces = {"text/plain"})
  public ResponseEntity<String> create(@RequestBody @Valid Authentication authentication) {
    return new ResponseEntity<>(jwtAuthAdapter.generateToken(authentication), HttpStatus.CREATED);
  }

}
