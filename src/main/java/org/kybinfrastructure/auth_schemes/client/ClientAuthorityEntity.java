package org.kybinfrastructure.auth_schemes.client;

import java.io.Serializable;
import java.time.OffsetDateTime;
import org.springframework.format.annotation.DateTimeFormat;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@EqualsAndHashCode
@Entity
@Table(name = "client_authority")
class ClientAuthorityEntity {

  @EmbeddedId
  private AuthorityId id;

  @NotNull
  @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
  @Column(name = "creation_date")
  private OffsetDateTime creationDate;

  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  @Getter
  @Setter
  @EqualsAndHashCode
  @Embeddable
  static class AuthorityId implements Serializable {

    @NotNull
    @Column(name = "client_id")
    private Long clientId;

    @NotNull
    @Column(name = "name")
    private String name;

  }

}
