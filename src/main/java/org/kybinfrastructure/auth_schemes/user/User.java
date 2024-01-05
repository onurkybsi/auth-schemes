package org.kybinfrastructure.auth_schemes.user;

import java.time.OffsetDateTime;
import java.util.List;
import org.kybinfrastructure.auth_schemes.common.Authority;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public final class User {

  @JsonProperty(value = "id", access = JsonProperty.Access.READ_ONLY)
  private Long id;

  @NotNull
  @Size(min = 0, max = 50)
  @JsonProperty(value = "firstName", required = true)
  private String firstName;

  @NotNull
  @Size(min = 0, max = 50)
  @JsonProperty(value = "lastName", required = true)
  private String lastName;

  @NotNull
  @Size(min = 0, max = 50)
  @JsonProperty(value = "email", required = true)
  private String email;

  @NotNull
  @Size(min = 0, max = 50)
  @JsonProperty(value = "password", required = true, access = JsonProperty.Access.WRITE_ONLY)
  private String password;

  @Valid
  @JsonProperty(value = "authorities", access = JsonProperty.Access.READ_ONLY)
  private List<Authority> authorities;

  @JsonProperty(value = "modificationDate", access = JsonProperty.Access.READ_ONLY)
  private OffsetDateTime modificationDate;

  @JsonProperty(value = "creationDate", access = JsonProperty.Access.READ_ONLY)
  private OffsetDateTime creationDate;

}
