package com.kyonggi.backend.auth.token.support;

import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

/**
 * Refresh Token 원문 생성기
 * 
 * SecureRandom:
 * - 토큰은 "예측 불가능"해야 한다
 * - java.util.Random은 예측 가능성이 있어 보안 토큰에 부적절
 * - SecureRandom은 암호학적으로 안전한 난수 생성기
 * 
 * Base64 URL-safe:
 * - 토큰을 쿠키/헤더/URL에 넣을 수 있게 안전한 문자셋으로 인코딩
 * - getUrlEncoder(): +, / 대신 URL-safe 문자(-, _) 사용
 * - withoutPadding(): 끝의 '=' 패딩 제거 → 더 깔끔한 토큰 형태
 */
@Component
@RequiredArgsConstructor
public class TokenGenerator {

    private static final int TOKEN_BYTES = 48;

    private final SecureRandom secureRandom;

    /** Refresh Token raw 생성 */
    public String generateRefreshToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
