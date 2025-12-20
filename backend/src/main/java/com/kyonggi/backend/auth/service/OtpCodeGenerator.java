package com.kyonggi.backend.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

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
