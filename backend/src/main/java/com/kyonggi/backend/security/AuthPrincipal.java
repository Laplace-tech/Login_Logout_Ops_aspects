package com.kyonggi.backend.security;

import com.kyonggi.backend.auth.domain.UserRole;

/**
 * SecurityContext에 들어갈 "인증된 사용자"의 최소 정보(Principal).
 *
 * - Spring Security는 Authentication(= 인증 결과)을 SecurityContext에 보관한다.
 * - 우리는 JWT 검증 성공 시 "누가 로그인했는지"를 표현할 값이 필요하고,
 *   그 역할을 이 Principal이 한다.
 *
 * - userId: DB의 사용자 식별자
 * - role: 인가(권한 체크)용 역할(enum)
 *
 * - JwtAuthenticationFilter가 JWT 검증 성공 시 AuthPrincipal을 만들어 Authentication에 넣는다.
 */
public record AuthPrincipal(Long userId, UserRole role) {

    // Spring Security 권한 문자열 규칙에 맞춘 ROLE_* 형태를 반환한다. 
    public String authority() {
        return "ROLE_" + role.name();
    }

}
