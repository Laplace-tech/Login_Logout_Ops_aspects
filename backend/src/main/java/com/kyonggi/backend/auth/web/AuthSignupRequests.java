package com.kyonggi.backend.auth.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public final class AuthSignupRequests {

    private AuthSignupRequests() {}

    public record OtpRequest(
            @NotBlank @Email String email
    ) {}

    public record OtpVerifyRequest(
            @NotBlank @Email String email,
            @NotBlank
            @Pattern(regexp = "^[0-9]{6}$", message = "6자리 숫자만 허용")
            String code
    ) {}

    public record SignupCompleteRequest(
            @NotBlank(message = "이메일은 필수입니다.")
            @Email(message = "이메일 형식이 올바르지 않습니다.")
            String email,

            @NotBlank(message = "비밀번호는 필수입니다.")
            @Size(max = 72, message = "비밀번호가 너무 깁니다.")
            String password,

            @NotBlank(message = "비밀번호 확인은 필수입니다.")
            @Size(max = 72, message = "비밀번호 확인이 너무 깁니다.")
            String passwordConfirm,

            @NotBlank(message = "닉네임은 필수입니다.")
            @Size(max = 50, message = "닉네임이 너무 깁니다.")
            String nickname
    ) {}
}
