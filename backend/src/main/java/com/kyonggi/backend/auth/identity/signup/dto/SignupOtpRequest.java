package com.kyonggi.backend.auth.identity.signup.dto;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.kyonggi.backend.global.jackson.TrimStringDeserializer;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * OTP 발송 요청 DTO
 * - 이메일 "형식"까지만 여기서 체크
 * - "경기대 도메인인지" 같은 정책 검증은 @Service 계층에서 2차로 처리한다.
 */
public record SignupOtpRequest(
        @JsonDeserialize(using = TrimStringDeserializer.class)
        @NotBlank 
        @Email String email
) {};
