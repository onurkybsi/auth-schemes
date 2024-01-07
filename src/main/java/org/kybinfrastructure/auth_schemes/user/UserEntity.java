package org.kybinfrastructure.auth_schemes.user;

import java.time.OffsetDateTime;
import java.util.List;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@Entity
@Table(name = "person")
class UserEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @NotNull
  @Size(min = 0, max = 50)
  @Column(name = "first_name")
  private String firstName;

  @NotNull
  @Size(min = 0, max = 50)
  @Column(name = "last_name")
  private String lastName;

  @NotNull
  @Size(min = 0, max = 255)
  @Email
  @Column(name = "email")
  private String email;

  @NotNull
  @Column(name = "hashed_password")
  private String hashedPassword;

  @NotNull
  @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
  @JoinColumn(name = "user_id")
  private List<UserAuthorityEntity> authorities;

  @NotNull
  @Column(name = "modification_date")
  private OffsetDateTime modificationDate;

  @NotNull
  @Column(name = "creation_date")
  private OffsetDateTime creationDate;

}
