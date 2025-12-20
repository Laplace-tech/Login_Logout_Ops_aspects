package com.kyonggi.backend.auth.web;

import com.kyonggi.backend.auth.service.SignupOtpService;
import com.kyonggi.backend.auth.service.SignupService;
import com.kyonggi.backend.auth.web.AuthSignupRequests.OtpRequest;
import com.kyonggi.backend.auth.web.AuthSignupRequests.OtpVerifyRequest;
import com.kyonggi.backend.auth.web.AuthSignupRequests.SignupCompleteRequest;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@Validated
@RequestMapping("/auth/signup")
@RequiredArgsConstructor
public class AuthSignupController {

    private final SignupOtpService otpService;
    private final SignupService signupService;

    @PostMapping("/otp/request")
    public ResponseEntity<Void> requestOtp(@RequestBody @Valid OtpRequest req) {
        otpService.requestSignupOtp(req.email());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/otp/verify")
    public ResponseEntity<Void> verifyOtp(@RequestBody @Valid OtpVerifyRequest req) {
        otpService.verifySignupOtp(req.email(), req.code());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/complete")
    public ResponseEntity<Void> complete(@RequestBody @Valid SignupCompleteRequest req) {
        signupService.completeSignup(req.email(), req.password(), req.passwordConfirm(), req.nickname());
        return ResponseEntity.status(201).build();
    }
}
