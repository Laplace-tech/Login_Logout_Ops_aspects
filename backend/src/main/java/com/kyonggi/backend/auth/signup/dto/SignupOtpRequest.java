package com.kyonggi.backend.auth.signup.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record SignupOtpRequest(
        @NotBlank
        @Email
        String email
        ) {
};
