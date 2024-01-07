package org.kybinfrastructure.auth_schemes.common;

import java.time.OffsetDateTime;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public final class Authority {

  @NotNull
  @Column(name = "name")
  @JsonProperty(value = "name", access = JsonProperty.Access.READ_ONLY)
  private Name name;

  @Column(name = "creation_date")
  @JsonProperty(value = "creationDate", access = JsonProperty.Access.READ_ONLY)
  private OffsetDateTime creationDate;

  public enum Name {

    BASIC, GET_ALL_USERS, CREATE_USER, GET_ALL_CLIENTS, CREATE_CLIENT

  }

}
