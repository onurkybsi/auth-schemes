package org.kybinfrastructure.auth_schemes.jwt;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public final class Authentication {

  @NotNull
  @Size(min = 0, max = 50)
  @JsonProperty(value = "email", required = true, access = JsonProperty.Access.WRITE_ONLY)
  private String email;

  @NotNull
  @Size(min = 0, max = 50)
  @JsonProperty(value = "password", required = true, access = JsonProperty.Access.WRITE_ONLY)
  private String password;

}
