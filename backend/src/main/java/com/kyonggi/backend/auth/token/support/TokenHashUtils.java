package com.kyonggi.backend.auth.token.support;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.springframework.stereotype.Component;

/**
 * 토큰 해시 유틸
 * 
 * - refresh token "원문"이 DB에 저장되면 유출 시 바로 악용 가능
 * - 그래서 DB에는 "해시(token_hash)"만 저장하고 실제 비교는 
 *   : incoming raw token -> (sha256Hex) -> DB token_hash와 비교
 */
@Component
public class TokenHashUtils {

    /**
     * Hashing 함수:
     * - 입력 문자열(raw token)을 SHA-256 해시 후 hex 문자열로 반환
     */
    public String sha256Hex(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            // SHA-256이 없으면 시스템이 정상 동작 불가 수준 -> 런타임 예외로 처리
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
