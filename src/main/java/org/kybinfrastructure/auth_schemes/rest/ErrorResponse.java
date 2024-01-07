package org.kybinfrastructure.auth_schemes.rest;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
final class ErrorResponse {

  private int status;
  private Object message;

}
