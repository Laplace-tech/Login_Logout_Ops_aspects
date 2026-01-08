package com.kyonggi.backend.auth.identity.login.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.domain.UserStatus;
import com.kyonggi.backend.auth.identity.signup.support.KyonggiEmailUtils;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.auth.token.domain.RefreshToken;
import com.kyonggi.backend.auth.token.service.RefreshTokenService;
import com.kyonggi.backend.auth.token.service.RefreshTokenService.Issued;
import com.kyonggi.backend.global.ApiException;
import com.kyonggi.backend.global.ErrorCode;
import com.kyonggi.backend.security.JwtService;

import lombok.RequiredArgsConstructor;

/**
 * 로그인 유스케이스
 * 
 * 책임:
 * - 이메일 정책 적용(경기대 도메인 강제 + 정규화)
 * - 자격 증명 검증(존재 여부/비밀번호)
 * - 계정 상태 정책(ACTIVE만 허용)
 * - 토큰 발급(access: body, refresh: cookie + DB 세션)
 *
* 보안:
 * - "이메일 없음"과 "비밀번호 불일치"는 동일 에러로 처리해 계정 유무 추측을 어렵게 한다.
 * - refresh는 원문을 DB에 저장하지 않고 해시만 저장(세션 통제)
 * 
 * 토큰 발급:
 * 1) JwtService: Access Token 발급(서명/클레임 생성) = Authentication: Bearer <token>
 *  - 짧은 TTL로 API 접근 권한 담당
 *  - 클라이언트는 Authorization 헤더에 담아 API 호출 시 사용
 *  
 * 2) RefreshTokenService: Refresh Token 발급 + DB 저장 = Set-Cookie: refresh=<token>; HttpOnly
 * - raw 토큰은 HttpOnly 쿠키로 클라이언트에 전달
 * - 서버에는 해시만 저장(유출 대비)
 */
@Service
@RequiredArgsConstructor
public class LoginService {

    private final UserRepository userRepository; 
    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;


    public LoginResult login(String rawEmail, String rawPassword, boolean rememberMe) {
        /**
         *  @DisplayName("email blank → 400 (컨트롤러 (검증) + Set-Cookie 없음")
         *  @DisplayName("password blank → 400 (컨트롤러 검증) + Set-Cookie 없음")
         */
        // 컨트롤러 @Valid가 있어도 서비스는 방어적으로 체크한다.
        if (isBlank(rawEmail) || isBlank(rawPassword)) {
            throw new ApiException(ErrorCode.INVALID_CREDENTIALS);
        }

        String email = normalizeKyonggiEmail(rawEmail); // @DisplayName("경기대 도메인 아님 → 400 EMAIL_DOMAIN_NOT_ALLOWED + Set-Cookie 없음")

        /**
         * 1) 사용자 조회 + 비밀번호 매칭
         * - 존재하지 않는 이메일/비밀번호 틀림 → "401 INVALID_CREDENTIALS" + Set-Cookie 없음
         * - 보안상 이유로 "이메일 없음"과 "비번 틀림"은 같은 에러로 뭉뚱그린다.
         * 
         * 2) 계정 상태 검사
         * - ACTIVE가 아니면 → "403 ACCOUNT_DISABLED" + Set-Cookie 없음
         */
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException(ErrorCode.INVALID_CREDENTIALS)); // @DisplayName("존재하지 않는 이메일 → 401 INVALID_CREDENTIALS + Set-Cookie 없음")

        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) { // @DisplayName("비밀번호 틀림 → 401 INVALID_CREDENTIALS + Set-Cookie 없음")
            throw new ApiException(ErrorCode.INVALID_CREDENTIALS);
        }

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ApiException(ErrorCode.ACCOUNT_DISABLED); // @DisplayName("비활성 계정 → 403 ACCOUNT_DISABLED + Set-Cookie 없음")
        }

        String accessToken = jwtService.issueAccessToken(user.getId(), user.getRole());
        Issued refreshToken = refreshTokenService.issue(user.getId(), rememberMe);

        /**
         * @DisplayName("login 성공: rememberMe=true 가 false 보다 refresh 쿠키 TTL(Max-Age)이 길다")
         * @DisplayName("login 성공: 이메일 normalize(공백/대소문자) 되어도 성공")
         */
        return new LoginResult(accessToken, refreshToken.raw(), rememberMe);
    }

    private String normalizeKyonggiEmail(String rawEmail) {
        KyonggiEmailUtils.validateKyonggiDomain(rawEmail);
        return KyonggiEmailUtils.normalize(rawEmail);
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    // 컨트롤러가 HTTP 응답으로 변환하기 위한 서비스 내부 결과.
    public record LoginResult(String accessToken, String refreshRaw, boolean rememberMe) {
    }
}
