package com.kyonggi.backend.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/*
 * app:
 *   auth:
 *     jwt:
 *       issuer: "kyonggi-board"
 *       access-ttl-seconds: 900
 *       secret: "..."   # HS256 서명용 비밀키 (최소 32바이트 권장)
 *     refresh:
 *       cookie-name: "KG_REFRESH"
 *       cookie-path: "/auth"
 *       cookie-same-site: "Lax"
 *       cookie-secure: false
 *       remember-me-seconds: 604800   # 7일
 *       session-ttl-seconds: 86400    # 1일
 */

/**
 * 인증 관련 설정 중에서 "JWT + Refresh 정책"을 담당
 *
 * @ConfigurationProperties(prefix = "app.auth"):
 *   application.yml 의 app.auth.* 값을 타입 안정성 있게 바인딩해준다.
 *
 * 사용처:
 *  - JwtService: issuer / accessTtlSeconds / secret
 *  - AuthCookieUtils / RefreshTokenService: refresh 쿠키 이름, path, TTL 정책
 */
@ConfigurationProperties(prefix = "app.auth")
public record AuthProperties(Jwt jwt, Refresh refresh) {
    
    // JWT 관련 설정: issuer/ttl/secret
    public record Jwt(
        String issuer, 
        long accessTtlSeconds, 
        String secret) {}


    // Refresh 관련 설정: 쿠키 옵션 + TTL 정책
    public record Refresh(
            String cookieName,         // 쿠키 이름 (예: KG_REFRESH)
            String cookiePath,         // 쿠키가 전송될 경로 (예: /auth)
            String cookieSameSite,     // SameSite 정책 (예: Lax)
            boolean cookieSecure,      // https에서만 전송할지 (운영 true)
            long rememberMeSeconds,    // rememberMe=true TTL(예: 7일)
            long sessionTtlSeconds     // rememberMe=false 서버 TTL(예: 1일)
    ) {}
}
