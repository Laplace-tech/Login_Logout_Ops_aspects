package com.kyonggi.backend.auth.identity.login.dto;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.kyonggi.backend.global.jackson.TrimStringDeserializer;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * [로그인 요청 DTO]
 * - email/password는 기본 형식 검증(@Email/@NotBlank)만 수행한다.
 * - "경기대 도메인 강제" 같은 정책 검증은 서비스(LoginService)에서 수행한다.
 */
public record LoginRequest(
    
        @JsonDeserialize(using = TrimStringDeserializer.class)
        @Email @NotBlank String email,
        
        @NotBlank String password,

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