package org.kybinfrastructure.auth_schemes.client;

import java.time.OffsetDateTime;
import java.util.List;
import org.kybinfrastructure.auth_schemes.common.Authority;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public final class Client {

  @JsonProperty(value = "id", access = JsonProperty.Access.READ_ONLY)
  private Long id;

  @NotNull
  @Size(min = 0, max = 50)
  @JsonProperty(value = "name")
  private String name;

  @JsonIgnore
  private String apiKey;

  @JsonIgnore
  private String hashedApiSecret;

  @JsonProperty(value = "authorities", access = JsonProperty.Access.READ_ONLY)
  private List<Authority> authorities;

  @JsonProperty(value = "modificationDate", access = JsonProperty.Access.READ_ONLY)
  private OffsetDateTime modificationDate;

  @JsonProperty(value = "creationDate", access = JsonProperty.Access.READ_ONLY)
  private OffsetDateTime creationDate;

}
