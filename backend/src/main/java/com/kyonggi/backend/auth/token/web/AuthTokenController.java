package com.kyonggi.backend.auth.token.web;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kyonggi.backend.auth.token.service.RefreshTokenService;
import com.kyonggi.backend.auth.token.support.AuthCookieUtils;
import com.kyonggi.backend.global.ApiException;
import com.kyonggi.backend.global.ErrorCode;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;


@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthTokenController {

    private final RefreshTokenService refreshTokenService;
    private final AuthCookieUtils cookieUtils;

    // POST: /auth/refresh
    @PostMapping("/refresh")
    public RefreshResponse refresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshRaw = cookieUtils.readRefreshCookie(request); // HttpOnly 쿠키에서 refresh raw를 읽는다.

        // refresh 토큰이 없거나 비어있으면 즉시 거절
        if (refreshRaw == null || refreshRaw.isBlank()) {
            throw new ApiException(ErrorCode.REFRESH_INVALID);
        }

        /**
         * ROTATE 수행:
         * - old refresh token 폐기
         * - 새로운 Refresh Token 및 Access Token 발급
         */
        var result = refreshTokenService.rotate(refreshRaw);

        cookieUtils.setRefreshCookie(response, result.newRefreshRaw(), result.rememberMe()); // 새 refresh를 쿠키로 내려준다.
        return new RefreshResponse(result.accessToken()); // accessToken은 body로 내려준다.
    }

    public record RefreshResponse(String accessToken) {}
}
