package com.kyonggi.backend.auth.signup.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record SignupOtpVerifyRequest(
        @NotBlank
        @Email
        String email,
        @NotBlank
        @Pattern(regexp = "^[0-9]{6}$", message = "6자리 숫자만 허용")
        String code
        ) {
}
