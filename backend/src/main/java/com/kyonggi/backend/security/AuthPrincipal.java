package com.kyonggi.backend.security;

/**
 * 서비스가 인증 완료 후 SecurityContext에 올릴 "로그인 사용자 정보" 모델
 * 
 * Spring Security의 Principal은 "인증된 사용자"를 나타내는 개념(인터페이스/관념)이고
 * 우리는 그 안에 들어갈 실제 데이터 형태를 record로 만든 것
 * 
 * JwtAuthenticationFilter에서 JWT 검증 성공 시, 이 AuthPrincipal을 만들어 Authentication에 넣는다.
 */
public record AuthPrincipal(Long userId, String role) {}
