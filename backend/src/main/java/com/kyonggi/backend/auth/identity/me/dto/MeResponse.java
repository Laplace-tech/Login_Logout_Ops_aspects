package com.kyonggi.backend.auth.identity.me.dto;

public record MeResponse (
    Long userId,
    String email,
    String nickname,
    String role,
    String status
) {}
