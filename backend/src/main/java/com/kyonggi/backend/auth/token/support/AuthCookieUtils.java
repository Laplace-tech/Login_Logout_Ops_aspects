package com.kyonggi.backend.auth.token.support;

import java.time.Duration;
import java.util.Arrays;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import com.kyonggi.backend.auth.config.AuthProperties;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;


/**
 * Refresh Token 쿠키 유틸
 *
 * - refresh token은 보통 "HttpOnly 쿠키"로 내려서 JS에서 접근 못하게 하여(XSS 방어) 탈취 위험을 낮춘다.
 * - 쿠키 옵션(path/samesite/secure/maxAge)을 한 곳에서 통일해서 관리하면 컨트롤러가 얇아지고, 설정 실수를 줄일 수 있다.
 *
 * ResponseCookie
 * - Spring이 제공하는 "Set-Cookie 헤더" 문자열 생성기
 * - 쿠키 옵션들을 안전하게 조합해서 최종 "Set-Cookie: ..." 값을 만들어준다.
 */
@Component
@RequiredArgsConstructor
public class AuthCookieUtils {

    private final AuthProperties props;

    // Refresh 쿠키 읽기
    public String readRefreshCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) 
            return null;

        String name = props.refresh().cookieName();
        return Arrays.stream(cookies)
                    .filter(cookie -> name.equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
    }

    /**
     * Refresh 쿠키 세팅
     * - rememberMe=true  -> Max-Age 설정(지속 쿠키)
     * - rememberMe=false -> Max-Age 미설정(세션 쿠키)
     */
    public void setRefreshCookie(HttpServletResponse response, String refreshRaw, boolean rememberMe) {
        var r = props.refresh();

        ResponseCookie.ResponseCookieBuilder b = ResponseCookie
                .from(r.cookieName(), refreshRaw)
                .httpOnly(true)
                .secure(r.cookieSecure())
                .path(r.cookiePath())
                .sameSite(r.cookieSameSite());

        if (rememberMe) {
            // ✅ Duration로 고정 (단위 실수 방지)
            b.maxAge(Duration.ofSeconds(r.rememberMeSeconds()));
        }
        // rememberMe=false -> session cookie

        response.addHeader(HttpHeaders.SET_COOKIE, b.build().toString());
    }

    /** Refresh 쿠키 삭제 */
    public void clearRefreshCookie(HttpServletResponse response) {
        var r = props.refresh();

        ResponseCookie cookie = ResponseCookie
                .from(r.cookieName(), "")
                .httpOnly(true)
                .secure(r.cookieSecure())
                .path(r.cookiePath())
                .sameSite(r.cookieSameSite())
                .maxAge(Duration.ZERO) // ✅ 즉시 만료
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
