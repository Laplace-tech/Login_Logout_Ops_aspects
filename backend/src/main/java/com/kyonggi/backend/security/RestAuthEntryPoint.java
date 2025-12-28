package com.kyonggi.backend.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * “인증이 필요한 엔드포인트”에 인증 없이 접근했을 때 호출되는 EntryPoint.
 *
 * - Authorization 헤더 자체가 없어서 인증이 비어있는 상태로 보호 리소스에 접근했을 때
 * - SecurityConfig의 authorize 규칙에서 authenticated() 걸린 요청인데 인증이 없을 때
 *
 * 반대로,
 * - Authorization 헤더가 있고 토큰이 invalid인 경우는 JwtAuthenticationFilter가 401을 내려버린다.
 */
@RequiredArgsConstructor
public class RestAuthEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException {

        // 이미 다른 필터가 응답을 만들어버린 경우라면 건드리지 않음
        if (response.isCommitted()) {
            return;
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 Unauthorized
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE); // "application/json"

        objectMapper.writeValue(response.getWriter(), Map.of(
                "code", "AUTH_REQUIRED",
                "message", "인증이 필요합니다."
        ));
    }
}
