package com.kyonggi.backend.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;


/**
 * @ConfigurationProperties(prefix = "app.auth"):
 * application.yml 의 app.auth.* 값을 타입 안정성 있게 바인딩해준다.
 */
@Validated
@ConfigurationProperties(prefix = "app.auth")
public record AuthProperties(Jwt jwt, Refresh refresh) {
    
    /**
     * Access Token(JWT) 관련 설정 (referenced by JwtService)
     * - issuer: 토큰 발급자 식별자 (kyonggi-board)
     * - accessTtlSeconds: Access Token 수명(초 단위)
     * - secret: HS256 서명을 위한 비밀키 문자열
     */
    public record Jwt(
        @NotBlank String issuer,
        @Min(1) long accessTtlSeconds, 
        @NotBlank @Size(min = 32) String secret
    ) {}


    /**
     * Refresh Token + 쿠키 관련 설정 (referenced by AuthCookieUtils, RefreshTokenService)
     * - cookieName: Refresh 토큰을 담을 쿠키 이름 (KG_REFRESH)
     * - cookiePath: 이 경로에 해당하는 요청에만 쿠키를 같이 전송 (/auth)
     * - cookieSameSite: SameSite 정책 (Lax / Strict / None)
     * - cookieSecure: https 에서만 전송 여부 (운영에선 true 권장)
     * - rememberMeSeconds: rememberMe=true 일 때 서버 측 세션 TTL (ex: 7일)
     * - sessionTtlSeconds: rememberMe=false 일 때 서버 측 세션 TTL (ex: 1일)
     */
    public record Refresh(
            @NotBlank String cookieName,         
            @NotBlank String cookiePath,        
            @NotBlank String cookieSameSite,  
            boolean cookieSecure,     
            @Min(1) long rememberMeSeconds,  
            @Min(1) long sessionTtlSeconds    
    ) {}
}
