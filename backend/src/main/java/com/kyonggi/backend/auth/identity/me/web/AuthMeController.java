package com.kyonggi.backend.auth.identity.me.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kyonggi.backend.auth.identity.me.dto.MeResponse;
import com.kyonggi.backend.auth.identity.me.service.MeService;
import com.kyonggi.backend.security.AuthPrincipal;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthMeController {
    
    private final MeService meService;

    @GetMapping("/me")
    public MeResponse me(@AuthenticationPrincipal AuthPrincipal principal) {
        return meService.me(principal);
    }

}
