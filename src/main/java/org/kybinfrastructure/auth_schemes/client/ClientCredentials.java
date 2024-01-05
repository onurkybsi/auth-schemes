package org.kybinfrastructure.auth_schemes.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public final class ClientCredentials {

  @JsonProperty(value = "apiKey", access = JsonProperty.Access.READ_ONLY)
  private String apiKey;

  @JsonProperty(value = "apiSecret", access = JsonProperty.Access.READ_ONLY)
  private String apiSecret;

}
