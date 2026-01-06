package com.kyonggi.backend.auth.token.dto;

/**
 * /auth/refresh 응답 바디
 * - access token은 바디로 내려준다.
 * - refresh token은 HttpOnly 쿠키로 내려간다.
 */
public record RefreshResponse(String accessToken) {}