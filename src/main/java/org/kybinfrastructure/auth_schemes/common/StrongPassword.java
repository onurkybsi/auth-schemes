package org.kybinfrastructure.auth_schemes.common;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.regex.Pattern;
import org.kybinfrastructure.auth_schemes.common.StrongPassword.StrongPasswordValidator;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = StrongPasswordValidator.class)
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface StrongPassword {

  String message() default "password is not strong enough";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};

  static class StrongPasswordValidator implements ConstraintValidator<StrongPassword, String> {

    private static final Pattern RGX_STRONG_PASSWORD = Pattern
        .compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#&()-[{}]:;',?/*~$^+=<>]).{8,20}$"); // NOSONAR

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
      if (value == null) {
        return false;
      }
      return RGX_STRONG_PASSWORD.matcher(value).matches();
    }

  }

}
