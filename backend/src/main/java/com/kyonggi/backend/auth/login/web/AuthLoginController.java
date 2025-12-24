package com.kyonggi.backend.auth.login.web;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kyonggi.backend.auth.config.AuthProperties;
import com.kyonggi.backend.auth.login.dto.LoginRequest;
import com.kyonggi.backend.auth.login.dto.LoginResponse;
import com.kyonggi.backend.auth.login.service.LoginService;
import com.kyonggi.backend.auth.token.support.AuthCookieUtils;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

/**
 * 로그인 API 컨트롤러 (web 계층)
 * 
 * 컨트롤러가 해야 할 일(=얇게 유지해야 함)
 * 1) HTTP 요청(JSON)을 DTO로 역직렬화 (@RequestBody)
 * 2) DTO에 대한 1차 검증 (@Valid)
 * 3) 실제 비즈니스 로직은 서비스(@Service)로 위임
 * 4) 서비스 결과를 HTTP 응답으로 변환
 * 
 * 이 엔드포인트가 반환하는 것
 * - Access Token: 응답 body(JSON)로 반환 (프론트가 메모리에 들고 있다가 Authorization 헤더에 붙임)
 * - Refresh Token: HttpOnly 쿠키(Set-Cookie)로 반환 (JS에서 접근 불가 -> XSS 방어)
 * 
 * - Access Token: 짧은 수명(자주 갱신), 매 요청 Authorization: Bearer ... 로 사용
 * - Refresh Token: 긴 수명(재발급용), 탈취 위험 낮추려고 HttpOnly 쿠키로 보관 + 서버(DB)에서 세션 통제
 */

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthLoginController {

    private final LoginService loginService; // 로그인 비즈니스 로직(인증/토큰 발급)을 담당
    private final AuthCookieUtils cookieUtils; // refresh token 쿠키를 생성/삭제하는 유틸
    private final AuthProperties authProps; // application.yml의 app.auth.* 설정 바인딩 값

    /**
     * POST /auth/login
     *
     * Request body(JSON) 예시
     * {
     *   "email": "add28482848@kyonggi.ac.kr",
     *   "password": "password123!",
     *   "rememberMe": true
     * }
     *
     * Response
     * - Set-Cookie: KG_REFRESH=<refreshRaw>; HttpOnly; ...
     * - Body: { "accessToken": "..." }
     */
    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest req, HttpServletResponse response) {
        
        /**
         * LoginService 호출:
         * - access token(JWT) 발급, 서버는 JWT 토큰을 검증만 한다.(stateless)
         * - refresh token(raw) 발급 + DB에는 hash 저장
         */
        var result = loginService.login(
                        req.email(), 
                        req.password(), 
                        req.rememberMeOrFalse()
                    );

        // 2) refresh 설정을 한 번에 꺼내서 (중복 호출 제거)
        var refresh = authProps.refresh();

        // "Refresh Token"을 HttpOnly 쿠키로 세팅
        cookieUtils.setRefreshCookie(
                response,
                refresh.cookieName(),
                result.refreshRaw(), // 쿠키에 들어갈 refresh token의 "원문" 
                refresh.cookiePath(),
                refresh.cookieSameSite(),
                refresh.cookieSecureOrFalse(), // cookieSecure Boolean을 안전하게 boolean으로 변환
                result.rememberMe(),
                refresh.rememberMeSeconds()
        );

        // "Access Token"은 body로 반환 -> 프론트는 이후 API 호출 시 Authrization 헤더로 전송
        return new LoginResponse(result.accessToken());
    }
}
