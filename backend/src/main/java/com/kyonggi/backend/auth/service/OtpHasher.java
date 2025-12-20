package com.kyonggi.backend.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OtpHasher {

    // 주입받는 필드는 lowerCamelCase로
    private final PasswordEncoder passwordEncoder;

    public String hash(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("OTP raw code must not be blank");
        }
        return passwordEncoder.encode(raw);
    }

    public boolean matches(String raw, String hash) {
        if (raw == null || raw.isBlank() || hash == null || hash.isBlank()) {
            return false;
        }
        return passwordEncoder.matches(raw, hash);
    }
}
