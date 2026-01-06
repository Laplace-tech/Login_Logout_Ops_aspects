package com.kyonggi.backend.auth.token.support;

import java.time.Duration;
import java.util.Arrays;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import com.kyonggi.backend.auth.config.AuthProperties;
import com.kyonggi.backend.auth.config.AuthProperties.Refresh;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Refresh Token 쿠키 유틸
 *
 * - refresh token은 보통 "HttpOnly 쿠키"로 내려서 JS에서 접근 못하게 해서(XSS 방어) 탈취 위험을 낮춘다.
 * - 쿠키 옵션(path/samesite/secure/maxAge)을 한 곳에서 통일해서 관리하면 컨트롤러가 얇아지고, 설정 실수를 줄일 수
 * 있다.
 *
 * ResponseCookie
 * - Spring이 제공하는 "Set-Cookie 헤더" 문자열 생성기
 * - 쿠키 옵션들을 안전하게 조합해서 최종 "Set-Cookie: ..." 값을 만들어준다.
 */
@Component
@RequiredArgsConstructor
public class AuthCookieUtils {

    private final AuthProperties props;

    /** Refresh 쿠키 읽기 (없으면 null) */
    public String readRefreshCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) return null;

        String cookieName = props.refresh().cookieName();

        return Arrays.stream(cookies)
                .filter(c -> cookieName.equals(c.getName()))
                .map(Cookie::getValue)
                .map(v -> v == null ? null : v.trim())
                .filter(v -> v != null && !v.isBlank())
                .findFirst()
                .orElse(null);
    }

    /**
     * Refresh 쿠키 세팅
     * - rememberMe=true  -> 긴 TTL (Max-Age = rememberMeSeconds)
     * - rememberMe=false -> 짧은 TTL (Max-Age = sessionTtlSeconds)
     */
    public void setRefreshCookie(HttpServletResponse response, String refreshRaw, boolean rememberMe) {
        if (refreshRaw == null || refreshRaw.isBlank()) {
            // 값이 비정상이면 쿠키 세팅 자체를 하지 않는 게 안전
            return;
        }

        Refresh refresh = props.refresh();

        ResponseCookie.ResponseCookieBuilder builder = baseRefreshCookie(refreshRaw);

        long ttlSeconds = rememberMe ? refresh.rememberMeSeconds() : refresh.sessionTtlSeconds();
        builder.maxAge(Duration.ofSeconds(ttlSeconds));

       response.addHeader(HttpHeaders.SET_COOKIE, builder.build().toString());
    }

    /** Refresh 쿠키 삭제 (속성(path/sameSite/secure)이 같아야 브라우저가 제대로 삭제함) */
    public void clearRefreshCookie(HttpServletResponse response) {
        ResponseCookie cookie = baseRefreshCookie("deleted")
                .maxAge(Duration.ZERO) // 즉시 만료
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private ResponseCookie.ResponseCookieBuilder baseRefreshCookie(String value) {
        Refresh r = props.refresh();
        return ResponseCookie.from(r.cookieName(), value)
                .httpOnly(true)
                .secure(r.cookieSecure())
                .path(r.cookiePath())
                .sameSite(r.cookieSameSite());
    }

}
