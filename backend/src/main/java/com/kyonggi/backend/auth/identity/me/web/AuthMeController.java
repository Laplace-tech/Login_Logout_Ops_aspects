package com.kyonggi.backend.auth.identity.me.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kyonggi.backend.auth.identity.me.dto.MeResponse;
import com.kyonggi.backend.auth.identity.me.service.MeService;
import com.kyonggi.backend.security.AuthPrincipal;

import lombok.RequiredArgsConstructor;

/**
 * [내 정보 조회 API 컨트롤러]
 * 
 * 동작 흐름:
 * - JwtAuthenticationFilter가 AccessToken(JWT)을 검증한다.
 * - 검증 성공 시 SecurityContext에 Authentication(principal=AuthPrincipal)을 넣는다.
 * - @AuthenticationPrincipal로 principal을 주입받아 서비스에 전달한다.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthMeController {
    
    private final MeService meService;

    @GetMapping("/me")
    public MeResponse me(@AuthenticationPrincipal AuthPrincipal principal) {
        // 인증된 사용자의 "내 정보"를 반환한다.
        return meService.me(principal); 
    }

}
