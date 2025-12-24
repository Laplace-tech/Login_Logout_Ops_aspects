package com.kyonggi.backend.auth.login.dto;

/**
 * 로그인 응답 DTO
 * 
 * - accessToken만 body로 내려준다 
 * - refresh token은 body에 넣지 않고, HttpOnly 쿠키(Set-Cookie)로 내려주는 구조
 * 
 * 1) accessToken -> body
 * - 짧은 TTL
 * - 프론트가 메모리에 들고 있다가 Authorization 헤더로 사용
 * 
 * 2) refreshToken -> HttpOnly
 * - 탈취되면 위험(수명이 길 수 있음)
 * - JS가 접근 못하게 HttpOnly 쿠키로 내려서 XSS 위험을 줄임
 */
public record LoginResponse(String accessToken) {}
