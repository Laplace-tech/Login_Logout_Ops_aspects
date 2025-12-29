package com.kyonggi.backend.security;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.kyonggi.backend.global.ErrorCode;

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

    private final SecurityErrorWriter errorWriter;

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException {

        errorWriter.write(response, ErrorCode.AUTH_REQUIRED); // ApiError.of(errorCode.name(), errorCode.defaultMessage())
    }
}
