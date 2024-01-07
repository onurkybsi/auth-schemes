package org.kybinfrastructure.auth_schemes.rest;

import java.util.List;
import org.kybinfrastructure.auth_schemes.common.exception.InvalidDataException;
import org.kybinfrastructure.auth_schemes.common.exception.NotExistException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
@RestControllerAdvice
class GlobalRestControllerExceptionHandler extends ResponseEntityExceptionHandler {

  @NonNull
  private final ObjectMapper objectMapper;

  @Override
  protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
      HttpHeaders headers, HttpStatusCode status, WebRequest request) {
    log.error(ex.getMessage(), ex);
    List<String> errorMessages =
        ex.getBindingResult().getFieldErrors().stream().map(FieldError::getDefaultMessage).toList();
    return new ResponseEntity<>(ErrorResponse.builder().status(HttpStatus.BAD_REQUEST.value())
        .message(errorMessages).build(), HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(NotExistException.class)
  protected ResponseEntity<Object> handleNotExistExceptions(NotExistException ex,
      WebRequest request) {
    log.error(ex.getMessage(), ex);
    return new ResponseEntity<>(ErrorResponse.builder().status(HttpStatus.NOT_FOUND.value())
        .message(ex.getMessage()).build(), HttpStatus.NOT_FOUND);
  }

  @ExceptionHandler(InvalidDataException.class)
  protected ResponseEntity<Object> handleInvalidDataExceptions(InvalidDataException ex,
      WebRequest request) {
    log.error(ex.getMessage(), ex);
    return new ResponseEntity<>(ErrorResponse.builder().status(HttpStatus.BAD_REQUEST.value())
        .message(ex.getMessage()).build(), HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(AccessDeniedException.class)
  protected ResponseEntity<Object> handleAccessDeniedException(AccessDeniedException ex,
      WebRequest request) {
    log.error(ex.getMessage(), ex);
    return new ResponseEntity<>(HttpStatus.FORBIDDEN);
  }

  @ExceptionHandler
  protected ResponseEntity<Object> handleRestOfExceptions(Exception ex, WebRequest request) {
    log.error(ex.getMessage(), ex);
    return new ResponseEntity<>(
        ErrorResponse.builder().status(HttpStatus.INTERNAL_SERVER_ERROR.value())
            .message("An unexpected error has occurred!").build(),
        HttpStatus.INTERNAL_SERVER_ERROR);
  }

}
