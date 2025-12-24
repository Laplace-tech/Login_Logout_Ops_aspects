package com.kyonggi.backend.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

/*
  otp:
    ttl-minutes: 10
    max-failures: 5
    resend-cooldown-seconds: 60
    daily-send-limit: 10
    hmac-secret: "${APP_OTP_HMAC_SECRET:local-dev-otp-secret-change-me}"
*/

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
        @NotBlank String hmacSecret
) {}