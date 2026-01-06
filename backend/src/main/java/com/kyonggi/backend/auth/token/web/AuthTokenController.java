package com.kyonggi.backend.auth.token.web;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kyonggi.backend.auth.token.dto.RefreshResponse;
import com.kyonggi.backend.auth.token.service.RefreshTokenService;
import com.kyonggi.backend.auth.token.support.AuthCookieUtils;
import com.kyonggi.backend.global.ApiException;
import com.kyonggi.backend.global.ErrorCode;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * 토큰 재발급(Refresh)
 *
 * - refresh raw는 HttpOnly 쿠키에서 읽는다.
 * - rotate 성공 시:
 *   1) 새 refresh raw를 쿠키로 내려줌
 *   2) 새 access token(JWT)을 바디로 내려줌
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthTokenController {

    private final RefreshTokenService refreshTokenService;
    private final AuthCookieUtils cookieUtils;

    @PostMapping("/refresh")
    public RefreshResponse refresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshRaw = cookieUtils.readRefreshCookie(request);
        
        // refresh 토큰이 없거나 비어있으면 즉시 거절
        if (refreshRaw == null || refreshRaw.isBlank()) {
            throw new ApiException(ErrorCode.REFRESH_INVALID); // 
        }

        /**
         * ROTATE 수행:
         * - old refresh token 폐기 & 새로운 Refresh,Access Token 발급
         * - 기존 토큰의 rememberMe를 이어받음
         */
        var result = refreshTokenService.rotate(refreshRaw);

        cookieUtils.setRefreshCookie(response, result.newRefreshRaw(), result.rememberMe());
        return new RefreshResponse(result.accessToken());
    }

}
