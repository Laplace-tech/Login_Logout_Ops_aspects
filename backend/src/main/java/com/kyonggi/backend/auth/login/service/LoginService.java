package com.kyonggi.backend.auth.login.service;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.auth.security.JwtService;
import com.kyonggi.backend.auth.signup.support.KyonggiEmailUtils;
import com.kyonggi.backend.auth.token.service.RefreshTokenService;
import com.kyonggi.backend.common.ApiException;

import lombok.RequiredArgsConstructor;

/**
 * 로그인 유스케이스 (@Service 계층)
 *  : 이메일 정책(도메인 강제) + 인증 (비번 검증) + 계정 상태 정책(ACTIVE) + 토큰 발급
 * 
 * - JwtService: Access Token 발급(서명/클레임 생성)
 * - RefreshTokenService: Refresh Token 발급 및 서버 저장(세션 유지 전략)
 */

@Service
@RequiredArgsConstructor
public class LoginService {

    private final UserRepository userRepository; // users 테이블 조회 담당
    private final PasswordEncoder passwordEncoder; // rawPassword를 해싱하여 DB의 password_hash와 비교

    private final JwtService jwtService; // Access Token (JWT) 발급 담당(서명/클레임)
    private final RefreshTokenService refreshTokenService; // Refresh Token 발급 + DB 저장 담당(서버 세션)

    /**
     * 로그인 실행
     * @param rawEmail
     * @param rawPassword
     * @param rememberMe
     * @return: accessToken + refreshRaw
     */
    public LoginResult login(String rawEmail, String rawPassword, boolean rememberMe) {
        
        // 이메일 도메인 강제 (@kyonggi.ac.kr)
        String email = KyonggiEmailUtils.normalizeEmail(rawEmail);
        KyonggiEmailUtils.validateDomain(email);

        // 이메일 기반 사용자(User) 조회
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(
                                HttpStatus.UNAUTHORIZED, // 401 Unauthorized
                                "INVALID_CREDENTIALS", 
                                "이메일 또는 비밀번호가 올바르지 않습니다.")
                            );

        // 비밀번호 검증 
        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            throw new ApiException(
                HttpStatus.UNAUTHORIZED, // 401 Unauthorized
                "INVALID_CREDENTIALS", 
                "이메일 또는 비밀번호가 올바르지 않습니다."
            );
        }

        // ACTIVE만 허용 (enum 값명 몰라도 name()으로 안전하게 체크)
        if (user.getStatus() == null || !"ACTIVE".equals(user.getStatus().name())) {
            throw new ApiException(
                HttpStatus.FORBIDDEN, // 403 Forbidden
                "ACCOUNT_DISABLED", 
                "사용할 수 없는 계정 상태입니다."
            );
        }

        /**
         * Access Token 발급(JWT)
         * - 짧은 TTL(예: 15분)로 API 호출 권한만 담당
         * - 클라이언트는 앞으로 API 호출 시:
         *   Authorization: Bearer <accessToken>
         */
        String access = jwtService.issueAccessToken(
            user.getId(), 
            user.getRole().name()
        );

        /**
         * Refresh Token 발급 + DB 저장
         * - refresh "raw"는 쿠키로 내려줘서, access 만료 시 재발급에 사용
         * - 서버 DB에는 raw refresh token이 아닌 hash만 저장됨(유출 대비)
         * - rememberMe에 따라:
         *    true: ttle 길게, 쿠키 maxAge 설정 (지속 쿠키)
         *    false: ttl 짧게, 쿠키 maxAge 미설정 (세션 쿠키)
         */
        var refresh = refreshTokenService.issue(
            user.getId(), 
            rememberMe
        );

        /**
         * @Controller가 이 결과로:
         * - refresh.raw()는 HttpOnly 쿠키로 세팅
         * - accessToken은 JSON body로 변환
         */
        return new LoginResult(access, refresh.raw(), rememberMe);
    }

    /**
     * 로그인 결과 DTO(서비스 내부 결과) - 컨트롤러에서 응답(LoginResponse) 만들 때 사용
     * - refreshRaw: cookie 세팅
     * - accessToken: body에 설정
     */
    public record LoginResult(
        String accessToken, 
        String refreshRaw, 
        boolean rememberMe
    ) {}
}
