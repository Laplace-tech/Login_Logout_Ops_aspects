package com.kyonggi.backend.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;


/**
 * OTP 관련 정책 설정
 *  - 보안 정책을 코드에 하드코딩하지 않고
 *  - 설정으로 분리 -> 변경/운영에 유리
 */
@Validated
@ConfigurationProperties(prefix = "app.otp")
public record OtpProperties(
        @Min(1) int ttlMinutes, 
        @Min(1) int maxFailures,
        @Min(1) int resendCooldownSeconds,
        @Min(1) int dailySendLimit,
        @NotBlank @Size(min = 32)String hmacSecret
) {}