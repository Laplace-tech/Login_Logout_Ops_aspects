package com.kyonggi.backend.auth.token.domain;

/**
 * RefreshToken이 폐기(revoke)된 이유
 * 
 * - ROTATED: 정상적인 refresh rotation 과정에서 기존 토큰을 폐기한 경우
 * - LOGOUT: 사용자가 로그아웃에서 서버가 세션을 종료한 경우 
 */
public enum RefreshRevokeReason {
    ROTATED,
    LOGOUT
}
