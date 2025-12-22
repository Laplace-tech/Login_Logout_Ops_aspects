package com.kyonggi.backend.auth.signup.web;

import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kyonggi.backend.auth.signup.dto.SignupCompleteRequest;
import com.kyonggi.backend.auth.signup.dto.SignupOtpRequest;
import com.kyonggi.backend.auth.signup.dto.SignupOtpVerifyRequest;
import com.kyonggi.backend.auth.signup.service.SignupOtpService;
import com.kyonggi.backend.auth.signup.service.SignupService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@Validated
@RequestMapping("/auth/signup")
@RequiredArgsConstructor
public class AuthSignupController {

    private final SignupOtpService otpService;
    private final SignupService signupService;

    @PostMapping("/otp/request")
    public ResponseEntity<Void> requestOtp(@RequestBody @Valid SignupOtpRequest req) {
        otpService.requestSignupOtp(req.email());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/otp/verify")
    public ResponseEntity<Void> verifyOtp(@RequestBody @Valid SignupOtpVerifyRequest req) {
        otpService.verifySignupOtp(req.email(), req.code());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/complete")
    public ResponseEntity<Void> complete(@RequestBody @Valid SignupCompleteRequest req) {
        signupService.completeSignup(req.email(), req.password(), req.passwordConfirm(), req.nickname());
        return ResponseEntity.status(201).build();
    }
}
