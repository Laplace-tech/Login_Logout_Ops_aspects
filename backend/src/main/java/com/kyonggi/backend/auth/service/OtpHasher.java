package com.kyonggi.backend.auth.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class OtpHasher {
    private static final PasswordEncoder ENCODER = new BCryptPasswordEncoder();

    public static String hash(String raw) {
        return ENCODER.encode(raw);
    }

    public static boolean matches(String raw, String hash) {
        return ENCODER.matches(raw, hash);
    }
}
