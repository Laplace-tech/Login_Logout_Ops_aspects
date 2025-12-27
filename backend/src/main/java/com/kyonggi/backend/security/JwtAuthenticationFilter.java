package com.kyonggi.backend.security;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ERROR_CODE = "ACCESS_INVALID";
    private static final String ERROR_MESSAGE = "엑세스 토큰이 유효하지 않습니다.";

    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // 이미 앞단에서 인증이 되어 있으면 그냥 패스
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = resolveToken(request);
        if (token == null) {
            // Authorization 헤더 없거나 Bearer 형식이 아니면, 이 필터는 그냥 넘김
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // 1) JWT 검증 → 우리 서비스의 Principal 로 복원
            AuthPrincipal principal = jwtService.verifyAccessToken(token);

            // 2) 권한(ROLE_*) 세팅
            var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + principal.role()));

            // 3) UsernamePasswordAuthenticationToken 생성해서 SecurityContext에 올리기
            var authentication = new UsernamePasswordAuthenticationToken(
                    principal,
                    null,
                    authorities
            );
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 4) 나머지 필터/컨트롤러로 계속 진행
            filterChain.doFilter(request, response);

        } catch (JwtService.InvalidJwtException ex) {
            // JWT가 잘못됐으면 인증정보 지우고 401 + JSON 에러 응답
            SecurityContextHolder.clearContext();
            handleInvalidJwt(response);
        }
    }

    /**
     * Authorization 헤더에서 Bearer 토큰만 뽑아내는 헬퍼.
     * 없거나 형식이 다르면 null 리턴.
     */
    private String resolveToken(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(authHeader == null || authHeader.isBlank()) 
            return null;
        if(!authHeader.startsWith(BEARER_PREFIX))
            return null;
        return authHeader.substring(BEARER_PREFIX.length()).trim();
    }

    /**
     * JWT 유효하지 않을 때 401 + JSON 바디 내려주는 처리.
     */
    private void handleInvalidJwt(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 Unauthorized
        response.setContentType(MediaType.APPLICATION_JSON_VALUE); // application/json

        Map<String, Object> body = Map.of(
            "code", ERROR_CODE, 
            "message", ERROR_MESSAGE
        );

        objectMapper.writeValue(response.getWriter(), body);
    }

}
