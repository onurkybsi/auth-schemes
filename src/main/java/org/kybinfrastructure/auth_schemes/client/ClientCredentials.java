package org.kybinfrastructure.auth_schemes.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

@AllArgsConstructor
@Data
@ToString
public final class ClientCredentials {

  @JsonProperty(value = "apiKey", access = JsonProperty.Access.READ_ONLY)
  private String apiKey;

  @JsonProperty(value = "clientSecret", access = JsonProperty.Access.READ_ONLY)
  private String clientSecret;

}
