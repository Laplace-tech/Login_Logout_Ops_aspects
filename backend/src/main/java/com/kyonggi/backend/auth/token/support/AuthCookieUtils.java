package com.kyonggi.backend.auth.token.support;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletResponse;


/**
 * Refresh Token 쿠키 유틸
 *
 * - refresh token은 보통 "HttpOnly 쿠키"로 내려서
 *   JS에서 접근 못하게 하여(XSS 방어) 탈취 위험을 낮춘다.
 * - 쿠키 옵션(path/samesite/secure/maxAge)을 한 곳에서 통일해서 관리하면
 *   컨트롤러가 얇아지고, 설정 실수를 줄일 수 있다.
 *
 * ResponseCookie
 * - Spring이 제공하는 "Set-Cookie 헤더" 문자열 생성기
 * - 쿠키 옵션들을 안전하게 조합해서 최종 "Set-Cookie: ..." 값을 만들어준다.
 */
@Component
public class AuthCookieUtils {

    /**
     * Refresh 쿠키 세팅
     *
     * @param response           서블릿 응답 객체(헤더에 Set-Cookie 추가)
     * @param cookieName         쿠키 이름 (예: KG_REFRESH)
     * @param refreshRaw         refresh token 원문(쿠키에 들어갈 값)
     * @param path               쿠키가 유효한 경로 (예: /auth)
     * @param sameSite           SameSite 정책 (Lax/Strict/None)
     * @param secure             Secure 플래그(https에서만 전송) - 운영은 보통 true
     * @param rememberMe         true면 지속 쿠키, false면 세션 쿠키
     * @param rememberMeSeconds  rememberMe=true일 때 쿠키 유지 시간
     *
     * - rememberMe=true  → maxAge 설정 → 브라우저 재시작해도 쿠키 유지(지속 쿠키)
     * - rememberMe=false → maxAge 미설정 → 브라우저 종료 시 쿠키 삭제(세션 쿠키)
     */
    public void setRefreshCookie(HttpServletResponse response,
                                 String cookieName,
                                 String refreshRaw,
                                 String path,
                                 String sameSite,
                                 boolean secure,
                                 boolean rememberMe,
                                 long rememberMeSeconds) {

        // ResponseCookie.from(...)은 내부 빌더(ResponseCookieBuilder)를 반환
        // → 여기서 옵션을 체이닝으로 추가하고 마지막에 build()로 문자열을 만든다.
        ResponseCookie.ResponseCookieBuilder b = ResponseCookie.from(cookieName, refreshRaw)
                .httpOnly(true)     // ✅ JS(document.cookie) 접근 불가 → XSS에 강함
                .secure(secure)     // ✅ https에서만 전송(운영 필수에 가깝고, SameSite=None이면 사실상 필수)
                .path(path)         // ✅ 쿠키 전송 범위를 제한(/auth 아래로만 보내게 가능)
                .sameSite(sameSite);// ✅ CSRF 방어에 중요한 옵션(Lax가 기본적으로 무난)

        if (rememberMe) {
            // 지속 쿠키(브라우저를 닫아도 유지)
            b.maxAge(rememberMeSeconds);
        }
        // rememberMe=false면 maxAge 미설정 => 세션 쿠키(브라우저 종료 시 삭제)

        // Set-Cookie 헤더를 추가하면 브라우저가 쿠키를 저장한다.
        response.addHeader("Set-Cookie", b.build().toString());
        // 참고: response.addHeader(HttpHeaders.SET_COOKIE, ...) 로 써도 좋음
    }

    /**
     * Refresh 쿠키 삭제(클리어)
     *
     * =========================
     * 📌 쿠키 삭제 원리
     * =========================
     * - 같은 이름/경로(path)/옵션으로
     * - 값은 비우고("")
     * - maxAge=0 으로 내려주면 브라우저가 즉시 삭제한다.
     *
     * ⚠️ 주의:
     * - path가 다르면 "다른 쿠키"로 취급되어 삭제가 안 될 수 있다.
     * - 운영에서 domain 설정을 쓰면 domain도 동일하게 맞춰야 삭제가 된다.
     */
    public void clearRefreshCookie(HttpServletResponse response,
                                   String cookieName,
                                   String path,
                                   String sameSite,
                                   boolean secure) {

        ResponseCookie cookie = ResponseCookie.from(cookieName, "")
                .httpOnly(true)
                .secure(secure)
                .path(path)
                .sameSite(sameSite)
                .maxAge(0)   // ✅ 즉시 만료 → 삭제
                .build();

        response.addHeader("Set-Cookie", cookie.toString());
    }
}
