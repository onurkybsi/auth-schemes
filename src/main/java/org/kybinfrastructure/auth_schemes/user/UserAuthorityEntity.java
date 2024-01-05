package org.kybinfrastructure.auth_schemes.user;

import java.io.Serializable;
import java.time.OffsetDateTime;
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
@Table(name = "user_authority")
class UserAuthorityEntity {

  @EmbeddedId
  private AuthorityId id;

  @NotNull
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
    @Column(name = "user_id")
    private Long userId;

    @NotNull
    @Column(name = "name")
    private String name;

  }

}
