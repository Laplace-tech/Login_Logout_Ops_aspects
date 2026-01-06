package com.kyonggi.backend.auth.token.web;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.kyonggi.backend.auth.token.domain.RefreshRevokeReason;
import com.kyonggi.backend.auth.token.service.RefreshTokenService;
import com.kyonggi.backend.auth.token.support.AuthCookieUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;


/**
 * 로그아웃
 * - refresh 쿠키가 없거나, DB에 없거나, 이미 revoked여도 -> 그냥 성공(멱등)
 * - 서버 쪽 RefreshToken revoke + 클라이언트 쿠키 삭제
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthLogoutController {
    
    private final RefreshTokenService refreshTokenService;
    private final AuthCookieUtils cookieUtils;

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshRaw = cookieUtils.readRefreshCookie(request);

        // 멱등 revoke
        refreshTokenService.revokeIfPresent(refreshRaw, RefreshRevokeReason.LOGOUT);

        // 쿠키는 항상 삭제 시도
        cookieUtils.clearRefreshCookie(response);
    }


}
