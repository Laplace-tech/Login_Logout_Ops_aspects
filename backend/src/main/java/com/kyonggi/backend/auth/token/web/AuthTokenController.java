package com.kyonggi.backend.auth.token.web;

import java.time.Duration;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kyonggi.backend.auth.config.AuthProperties;
import com.kyonggi.backend.auth.token.service.RefreshTokenService;
import com.kyonggi.backend.common.ApiException;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthTokenController {

    private final RefreshTokenService refreshTokenService;
    private final AuthProperties props;

    @PostMapping("/refresh")
    public RefreshResponse refresh(
            @CookieValue(name = "KG_REFRESH", required = false) String refreshRaw,
            HttpServletResponse response
    ) {
        if (refreshRaw == null || refreshRaw.isBlank()) {
            throw new ApiException(
                HttpStatus.UNAUTHORIZED, 
                "REFRESH_MISSING", 
                "리프레시 토큰이 없습니다.");
        }

        RefreshTokenService.RotateResult result = refreshTokenService.rotate(refreshRaw);

        // ✅ var로 빌더 받기 (Builder 타입이 아님)
        var cb = ResponseCookie.from("KG_REFRESH", result.newRefreshRaw())
                .httpOnly(true)
                .secure(false)     // 로컬/테스트 통과용 (테스트는 Secure 안 봄)
                .path("/auth")
                .sameSite("Lax");

        if (result.rememberMe()) {
            cb.maxAge(Duration.ofSeconds(props.refresh().rememberMeSeconds()));
        }

        response.addHeader(HttpHeaders.SET_COOKIE, cb.build().toString());
        return new RefreshResponse(result.accessToken());
    }

    public record RefreshResponse(String accessToken) {}
}
