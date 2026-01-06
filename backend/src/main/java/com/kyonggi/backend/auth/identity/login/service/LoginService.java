package com.kyonggi.backend.auth.identity.login.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.domain.UserStatus;
import com.kyonggi.backend.auth.identity.signup.support.KyonggiEmailUtils;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.auth.token.service.RefreshTokenService;
import com.kyonggi.backend.global.ApiException;
import com.kyonggi.backend.global.ErrorCode;
import com.kyonggi.backend.security.JwtService;

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

    private final UserRepository userRepository; 
    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService; // Access Token (JWT) 발급 담당(서명/클레임)
    private final RefreshTokenService refreshTokenService; // Refresh Token 발급 + DB 저장 담당(서버 세션)


    public LoginResult login(String rawEmail, String rawPassword, boolean rememberMe) {
        /**
         * 서비스 계층에서도 최소 방어(컨트롤러 @Valid를 믿지 않음)
         *  @DisplayName("email blank → 400 (컨트롤러 검증) + Set-Cookie 없음")
         *  @DisplayName("password blank → 400 (컨트롤러 검증) + Set-Cookie 없음")
         */
        if (rawEmail == null || rawEmail.isBlank() || rawPassword == null || rawPassword.isBlank()) {
            throw new ApiException(ErrorCode.INVALID_CREDENTIALS);
        }

        // 이메일 도메인 강제 (@kyonggi.ac.kr)
        String email = normalizeKyonggiEmail(rawEmail); // @DisplayName("경기대 도메인 아님 → 400 EMAIL_DOMAIN_NOT_ALLOWED + Set-Cookie 없음")

        // 사용자 조회 (보안상 "이메일 없음"과 "비번 틀림"은 같은 에러로 뭉개는 게 일반적)
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(ErrorCode.INVALID_CREDENTIALS)); // @DisplayName("존재하지 않는 이메일 → 401 INVALID_CREDENTIALS + Set-Cookie 없음")

        // 비밀번호 매칭 (incoming raw password를 해싱하여 USERS 테이블과 대조)
        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) { // @DisplayName("비밀번호 틀림 → 401 INVALID_CREDENTIALS + Set-Cookie 없음")
            throw new ApiException(ErrorCode.INVALID_CREDENTIALS);
        }

        // ACTIVE만 허용 (enum 값명 몰라도 name()으로 안전하게 체크) 
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ApiException(ErrorCode.ACCOUNT_DISABLED); // @DisplayName("비활성 계정 → 403 ACCOUNT_DISABLED + Set-Cookie 없음")
        }

        /**
         * Access Token 발급(JWT)
         * - 짧은 TTL(예: 15분)로 API 호출 권한만 담당
         * - 클라이언트는 앞으로 API 호출 시:
         *   Authorization: Bearer <accessToken> 헤더를 붙여서 요청
         */
        String accessToken = jwtService.issueAccessToken(user.getId(), user.getRole());

        /**
         * Refresh Token 발급 + DB 저장
         * - refresh "raw"는 쿠키로 내려줘서, access 만료 시 재발급에 사용
         * - 서버 DB에는 raw refresh token이 아닌 hash만 저장됨(유출 대비)
         * - rememberMe에 따라:
         *    true: ttle 길게, 쿠키 maxAge 설정 (지속 쿠키)
         *    false: ttl 짧게, 쿠키 maxAge 미설정 (세션 쿠키)
         */
         var refresh = refreshTokenService.issue(user.getId(), rememberMe);

        /**
         * @Controller가 이 결과로:
         * - refresh.raw()는 HttpOnly 쿠키로 세팅
         * - accessToken은 JSON body로 변환
         * 
         * @DisplayName("login 성공: rememberMe=true 가 false 보다 refresh 쿠키 TTL(Max-Age)이 길다")
         * @DisplayName("login 성공: 이메일 normalize(공백/대소문자) 되어도 성공")
         */
        return new LoginResult(accessToken, refresh.raw(), rememberMe);
    }

    private String normalizeKyonggiEmail(String rawEmail) {
        KyonggiEmailUtils.validateKyonggiDomain(rawEmail);
        return KyonggiEmailUtils.normalize(rawEmail);
    }

    /**
     * 서비스 내부 결과 DTO
     * - 컨트롤러는 이 값을 이용해서:
     *   (1) refreshRaw -> HttpOnly 쿠키
     *   (2) accessToken -> body(LoginResponse)
     */
    public record LoginResult(
            String accessToken,
            String refreshRaw,
            boolean rememberMe
    ) {}
}
