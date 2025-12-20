package com.kyonggi.backend.auth.web;

import com.kyonggi.backend.auth.service.SignupOtpService;
import com.kyonggi.backend.auth.service.SignupService;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@Validated
@RequestMapping("/auth/signup")
public class AuthSignupController {

    private final SignupOtpService otpService;
    private final SignupService signupService;

    public AuthSignupController(SignupOtpService otpService, SignupService signupService) {
        this.otpService = otpService;
        this.signupService = signupService;
    }

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
            @NotBlank @Email String email,
            @NotBlank @Size(min = 8, max = 72) String password,
            @NotBlank @Size(min = 2, max = 30) String nickname
    ) {}

    @PostMapping("/otp/request")
    public ResponseEntity<Void> requestOtp(@RequestBody @Validated OtpRequest req) {
        otpService.requestSignupOtp(req.email());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/otp/verify")
    public ResponseEntity<Void> verifyOtp(@RequestBody @Validated OtpVerifyRequest req) {
        otpService.verifySignupOtp(req.email(), req.code());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/complete")
    public ResponseEntity<Void> complete(@RequestBody @Validated SignupCompleteRequest req) {
        signupService.completeSignup(req.email(), req.password(), req.nickname());
        // 정책: 자동 로그인 X → 201 대신 204로도 OK. 여기선 201 느낌으로만.
        return ResponseEntity.status(201).build();
    }
}
