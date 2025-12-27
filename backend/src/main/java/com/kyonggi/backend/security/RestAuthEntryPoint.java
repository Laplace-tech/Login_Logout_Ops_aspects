package com.kyonggi.backend.security;

import java.io.IOException;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * 인증이 안 된 상태에서 보호된 리소스에 접근했을 때
 * 401 + JSON 에러 응답을 내려주는 엔트리포인트.
 * 
 *  - 로그인 안 하고 /api/me 같은 곳에 접근할 때
 *  - JWT 아예 없는 요청이 보호된 엔드포인트로 들어왔을 때
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

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> body = Map.of(
                "code", "AUTH_REQUIRED",
                "message", "인증이 필요합니다."
        );

        objectMapper.writeValue(response.getWriter(), body);
    }
}
