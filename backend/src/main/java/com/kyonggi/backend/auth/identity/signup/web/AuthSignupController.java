package com.kyonggi.backend.auth.identity.signup.web;

import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kyonggi.backend.auth.identity.signup.dto.SignupCompleteRequest;
import com.kyonggi.backend.auth.identity.signup.dto.SignupOtpRequest;
import com.kyonggi.backend.auth.identity.signup.dto.SignupOtpVerifyRequest;
import com.kyonggi.backend.auth.identity.signup.service.SignupOtpService;
import com.kyonggi.backend.auth.identity.signup.service.SignupService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

/**
 * 회원가입 관련 API 컨트롤러 
 * 
 * Controller 역할
 * - HTTP 요청/응답 처리
 * - DTO 검증 (@Valid)
 * - 서비스 호출
 */

@RestController
@Validated
@RequestMapping("/auth/signup")
@RequiredArgsConstructor
public class AuthSignupController {

    private final SignupOtpService otpService;
    private final SignupService signupService;

    // OTP 발급 요청
    @PostMapping("/otp/request")
    public ResponseEntity<Void> requestOtp(@RequestBody @Valid SignupOtpRequest req) {
        otpService.requestSignupOtp(req.email());
        // 성공 시 body 없이 204 No Content
        return ResponseEntity.noContent().build();
    }

    // OTP 검증
    @PostMapping("/otp/verify")
    public ResponseEntity<Void> verifyOtp(@RequestBody @Valid SignupOtpVerifyRequest req) {
        otpService.verifySignupOtp(req.email(), req.code());
        return ResponseEntity.noContent().build();
    }

    // 회원가입 완료
    @PostMapping("/complete")
    public ResponseEntity<Void> complete(@RequestBody @Valid SignupCompleteRequest req) {
        signupService.completeSignup(
            req.email(), 
            req.password(), 
            req.passwordConfirm(), 
            req.nickname()
        ); // 리소스 생성 완료 -> 201 Created
        return ResponseEntity.status(201).build();
    }
}
