package com.kyonggi.backend.auth.signup.support;

import org.springframework.http.HttpStatus;

import com.kyonggi.backend.common.ApiException;


public class KyonggiEmailUtils {

    public static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }

    /** 경기대 이메일 도메인 검증
     * 
     * - 비즈니스 규칙: @kyonggi.ac.kr 이메일만 가입 가능
     * - @Email 형식으로만 DTO에서 검증하고 학교 도메인 제한은 순수 비즈니즈 정책
     */
    public static void validateDomain(String normalizedEmail) {
        if (normalizedEmail == null || !normalizedEmail.endsWith("@kyonggi.ac.kr")) {
            throw new ApiException(
                HttpStatus.BAD_REQUEST, 
                "EMAIL_DOMAIN_NOT_ALLOWED",
                "@kyonggi.ac.kr 이메일만 가입할 수 있습니다.");
        }
    }
}
