package com.kyonggi.backend.auth.support;

import com.kyonggi.backend.common.ApiException;
import org.springframework.http.HttpStatus;

public class KyonggiEmailUtils {

    public static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }

    public static void validateDomain(String normalizedEmail) {
        if (normalizedEmail == null || !normalizedEmail.endsWith("@kyonggi.ac.kr")) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "EMAIL_DOMAIN_NOT_ALLOWED",
                    "@kyonggi.ac.kr 이메일만 가입할 수 있습니다.");
        }
    }
}
