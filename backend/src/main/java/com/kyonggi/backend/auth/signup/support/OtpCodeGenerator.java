package com.kyonggi.backend.auth.signup.support;

import java.security.SecureRandom;

import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class OtpCodeGenerator {

    private final SecureRandom secureRandom;

    // 6자리 숫자 (100000~999999)
    public String generate6Digits() {
        int n = secureRandom.nextInt(900_000) + 100_000;
        return Integer.toString(n);
    }
}
