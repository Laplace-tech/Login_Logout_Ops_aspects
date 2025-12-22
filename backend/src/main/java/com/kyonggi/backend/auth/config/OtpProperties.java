package com.kyonggi.backend.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

@Validated
@ConfigurationProperties(prefix = "app.otp")
public record OtpProperties(
        @Min(1) int ttlMinutes,
        @Min(1) int maxFailures,
        @Min(1) int resendCooldownSeconds,
        @Min(1) int dailySendLimit,
        @NotBlank String hmacSecret
) {}