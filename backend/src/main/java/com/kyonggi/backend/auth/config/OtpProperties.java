package com.kyonggi.backend.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.otp")
public record OtpProperties(
        int ttlMinutes,
        int maxFailures,
        int resendCooldownSeconds,
        int dailySendLimit
) {}
