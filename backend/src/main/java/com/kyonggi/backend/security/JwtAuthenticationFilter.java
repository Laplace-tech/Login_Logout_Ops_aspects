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
 * "Security Filter Chain"에서 "JWT 기반 인증"을 수행하는 인증 필터
 * 
 * 역할:
 * - 모든 요청에서 "Authorization: Bearer <token>" 헤더가 있으면 Access Token을 꺼낸다.
 * - JwtService로 JWT 서명/만료/issuer를 검증해서 AuthPrincipal(userId, role)을 얻는다.
 * - 검증이 성공하면 SecurityContext에 Authentication을 세팅한다.
 * 
 * 중요한 분리:
 * - "토큰이 없음" → 여기서 막지 않는다. 그냥 다음으로 넘김. (실제 차단은 SecurityConfig의 authorize 규칙 + EntryPoint가 담당)
 * - "토큰이 있는데 invalid" → 여기서 401 JSON 응답을 직접 내려준다.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final SecurityErrorWriter errorWriter;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // 이미 인증이 세팅되어 있으면(다른 필터/체인에서) 중복 인증 안 함
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        /**
         * @DisplayName("me: Authorization 없음 → 401 AUTH_REQUIRED (EntryPoint)")
         * @DisplayName("me: Bearer가 아닌 Authorization → 401 AUTH_REQUIRED (EntryPoint)")
         * @DisplayName("me: Authorization='Bearer ' (토큰 공백) → 401 AUTH_REQUIRED (EntryPoint)")
         */
        // Authorization: Bearer <ACCESS_JWT> 에서 Access Token(JWT) 추출
        String token = resolveToken(request);
        if (token == null) {
            // 토큰이 없으면 그냥 통과. (보호 리소스 차단은 EntryPoint/authorize에서)
            filterChain.doFilter(request, response);
            return;
        }

        try {
            /**
             * throw new InvalidJwtException("Invalid JWT", e)
             *  @DisplayName("me: 형식/서명/issuer/만료 등 검증 실패 JWT → 401 ACCESS_INVALID (Filter)")
             *  @DisplayName("me: refresh 토큰 문자열을 access처럼 사용 → 401 ACCESS_INVALID (Filter)")
             */
            // JWT 검증 → JwtParser로 토큰을 복원하여 AuthPrincipal를 만들어 반환 
            AuthPrincipal principal = jwtService.verifyAccessToken(token);

            // 권한(ROLE_*) 세팅: ROLE_USER
            var authorities = List.of(new SimpleGrantedAuthority(principal.authority()));

            // Spring Security가 이해하는 Authentication 생성
            var authentication = new UsernamePasswordAuthenticationToken(
                    principal,
                    null,
                    authorities
            );
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // SecurityContext에 인증 정보 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 다음 필터/컨트롤러로 진행
            filterChain.doFilter(request, response);
        } catch (JwtService.InvalidJwtException ex) {
            // 토큰이 "있는데" invalid라면 여기서 401 JSON으로 끝낸다.
            SecurityContextHolder.clearContext();
            errorWriter.write(response, ErrorCode.ACCESS_INVALID); // 내부에서: write(response, errorCode, errorCode.defaultMessage()); 호출
        }
    }

    /**
     * "Authorization: Bearer <token>" 헤더에서 <token>만 뽑아내는 헬퍼.
     * - 없거나 형식이 다르면 null 리턴.
     */
    private String resolveToken(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION); // Bearer <token>
        if(authHeader == null || authHeader.isBlank()) 
            return null;
        if(!authHeader.startsWith(BEARER_PREFIX)) 
            return null;

        String token = authHeader.substring(BEARER_PREFIX.length()).trim(); // <token>
        return token.isBlank() ? null : token;
    }

}
