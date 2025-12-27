package com.kyonggi.backend.auth.identity.login.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @Email @NotBlank String email, // 이메일 형식 검증
        @NotBlank String password, // 비밀번호 평문
        
        /**
         * rememberMe 옵션
         * - null 가능(Boolean)
         * - true: refresh token을 "지속 쿠키"로 내려줌(maxAge 설정) + 서버 TTL도 길게
         * - false(or null)이면: "세션 쿠기"로 내려줌(maxAge 미설정) + 서버 TTL도 상대적으로 짧게
         */
        Boolean rememberMe
) {
    public boolean rememberMeOrFalse() {
        return Boolean.TRUE.equals(rememberMe);
    }
}
