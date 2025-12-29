package com.kyonggi.backend.security;

import java.io.IOException;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.kyonggi.backend.global.ErrorCode;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Security Filter Chain에서 동작하는 JWT 인증 필터
 * 
 * - Authorization: Bearer <token> 헤더가 있으면 토큰을 꺼낸다. (Access Token(JWT))
 * - JwtService로 검증해서 AuthPrincipal(userId, role)을 얻는다.
 * - Spring Security가 이해할 수 있는 Authentication 객체를 만들어 SecurityContext에 넣는다.
 * - 다음 필터/컨트롤러로 흐름을 넘긴다.
 * 
 * 주의:
 * - "토큰이 없는 요청"은 여기서 막지 않는다. (실제로 막는 건 SecurityConfig의 authorize 규칙과 EntryPoint가 담당)
 * - "토큰이 있는데 invalid"면 여기서 401 Unauthorized를 직접 내려준다.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final SecurityErrorWriter errorWriter;

    @SuppressWarnings("null")
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

        // "Authorization: Bearer <token>" 여기에서 리프레쉬 토큰 원문을 추출
        String token = resolveToken(request);
        if (token == null) {
            // Authorization 헤더 없거나 Bearer 형식이 아니면, 이 필터는 그냥 넘김
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // JWT 검증 → JwtParser로 토큰을 복원하여 AuthPrincipal를 만들어 반환 
            AuthPrincipal principal = jwtService.verifyAccessToken(token);

            // Spring Security 권한 모델로 변환 (ROLE_ 접두사 관례)
            String roleName = principal.role().startsWith("ROLE_")
                ? principal.role()
                : "ROLE_" + principal.role();

            // 권한(ROLE_*) 세팅: ROLE_USER
            var authorities = List.of(new SimpleGrantedAuthority(roleName));

            // 3) UsernamePasswordAuthenticationToken 생성해서 SecurityContext에 주입
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
            /**
             * invalid token일 때 내려줄 401 JSON 응답.
             * EntryPoint는 “토큰 자체가 없어서 인증 실패”일 때 쓰고,
             * 여기서는 “토큰이 있는데 invalid”일 때 쓴다.
             */
            SecurityContextHolder.clearContext();
            errorWriter.write(response, ErrorCode.ACCESS_INVALID); // ApiError.of(errorCode.name(), errorCode.defaultMessage());
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

        String token = authHeader.substring(BEARER_PREFIX.length()).trim();
        return token.isBlank() ? null : token;
    }

}
