package com.kyonggi.backend.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

/*
app:
  auth:
    jwt:
      issuer: "kyonggi-board"
      access-ttl-seconds: 900
      secret: "${APP_AUTH_JWT_SECRET:local-dev-jwt-secret-change-me-32-bytes-min}"
    refresh:
      cookie-name: "KG_REFRESH"
      cookie-path: "/auth"
      cookie-same-site: "Lax"
      cookie-secure: false   # 로컬은 false, 운영은 true로 바꾸거나 profile로 분리
      remember-me-seconds: 604800  # 7d
      session-ttl-seconds: 86400   # rememberMe=false일 때 서버 만료(권장 1d)
*/

/**
 * - @ConfigurationProperties: application.yml -> 타입 안정 바인딩
 * - @Validated: 기동 시정 Bean Validation (잘못된 설정이면 바로 실패)
 */
@Validated
@ConfigurationProperties(prefix = "app.auth")
public record AuthProperties(
        @Valid Jwt jwt,
        @Valid Refresh refresh
) {

    // JWT 설정
    public record Jwt(
            @NotBlank String issuer, // 토큰 발급자(issuer)
            @Min(60) long accessTtlSeconds, // Access Token 유효 시간(초)
            @NotBlank String secret // JWT 서명용 비밀 키
    ) {}

    // Refresh 토큰 쿠키 설정
    public record Refresh(
            @NotBlank String cookieName, // Refresh Token 쿠키 이름
            @NotBlank String cookiePath, // 쿠키가 유효한 경로
            @NotBlank String cookieSameSite,
            Boolean cookieSecure,
            @Min(60) long rememberMeSeconds, // remember-me 선택 시 유지 시간
            @Min(60) long sessionTtlSeconds // remember-me 미사용 시 서버 세션 TTL
    ) {
        /** cookieSecure가 null이면 false로 취급 */
        public boolean cookieSecureOrFalse() {
            return Boolean.TRUE.equals(cookieSecure);
        }
            /** SameSite 값 제한(오타 방지) */
        public enum SameSite {
          Lax, Strict, None
        }
    }
}
