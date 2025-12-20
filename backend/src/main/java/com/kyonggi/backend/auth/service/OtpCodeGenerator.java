package com.kyonggi.backend.auth.service;

import java.security.SecureRandom;

public class OtpCodeGenerator {
    private static final SecureRandom RND = new SecureRandom();

    // 6자리 숫자
    public static String generate6Digits() {
        int n = RND.nextInt(1_000_000); // 0..999999
        return String.format("%06d", n);
    }
}
