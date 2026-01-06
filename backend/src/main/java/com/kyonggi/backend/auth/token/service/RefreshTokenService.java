package com.kyonggi.backend.auth.token.service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kyonggi.backend.auth.config.AuthProperties;
import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.auth.token.domain.RefreshRevokeReason;
import com.kyonggi.backend.auth.token.domain.RefreshToken;
import com.kyonggi.backend.auth.token.repo.RefreshTokenRepository;
import com.kyonggi.backend.auth.token.support.TokenGenerator;
import com.kyonggi.backend.auth.token.support.TokenHashUtils;
import com.kyonggi.backend.global.ApiException;
import com.kyonggi.backend.global.ErrorCode;
import com.kyonggi.backend.security.JwtService;

import lombok.RequiredArgsConstructor;

/**
 * Refresh Token 발급/로테이션 서비스
 * 
 * Refresh Token: Access Token의 TTL이 만료됐을 때 "재로그인 없이" Access Token을 다시 받기 위한 토큰
 * - Access Token 보다 TTL이 길다 (rememberMe면 더 길게)
 * 
 * DB에는 sha256 해시만 저장
 * - 검증 시, incoming raw -> sha256 -> DB hash 비교)
 * - 클라이언트에는 raw를 HttpOnly 쿠키로 내려준다
 * 
 * rememberMe 정책
 * - rememberMe=true  → 긴 TTL(7d 같은)
 * - rememberMe=false → 짧은 TTL(1d 같은)
 */ 
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    private final JwtService jwtService;

    private final TokenGenerator tokenGenerator; // 랜덤 refresh raw 생성(SecureRandom)
    private final TokenHashUtils hashUtils;      // raw -> sha256Hex(hash) 변환

    private final AuthProperties props;       
    private final Clock clock;                 

    /**
     * Refresh Token 발급: 
     * - "토큰 발급" + "DB 저장"이 한 단위의 유스케이스로 같이 성공/실패 해야 함
     * - raw 생성 -> sha256Hex로 해싱 -> DB 저장
     * - 클라이언트에는 raw를 쿠키로 내려줘야 하므로 raw를 반환한다.
     */
    @Transactional
    public Issued issue(Long userId, boolean rememberMe) {
        if (userId == null) 
            throw new IllegalArgumentException("userId must not be null");

        LocalDateTime now = LocalDateTime.now(clock);
        long ttlSeconds = resolveTtlSeconds(rememberMe);
        LocalDateTime expiresAt = now.plusSeconds(ttlSeconds);

        String raw = tokenGenerator.generateRefreshToken();
        if (raw == null || raw.isBlank()) {
            throw new IllegalStateException("generated refresh token is blank");
        }

        String hash = hashUtils.sha256Hex(raw);
        
        // "토큰 발급" + "DB 저장"
        refreshTokenRepository.save(RefreshToken.issue(userId, hash, rememberMe, now, expiresAt));
        return new Issued(raw, expiresAt, rememberMe); // 컨트롤러가 쿠키로 내려주기 위해 raw를 반환
    }

    /**
     * Refresh Token "회전(재발급)"
     * 
     * 동시성 방어:
     * - old refresh row를 PESSIMISTIC_WRITE로 잠가서 
     *    같은 토큰을 두 번 성공하는 것을 구조적으로 차단한다.
     */
    @Transactional
    public RotateResult rotate(String oldRefreshRaw) {
        if (oldRefreshRaw == null || oldRefreshRaw.isBlank()) {
            throw new ApiException(ErrorCode.REFRESH_INVALID); // @DisplayName("리프레시: 쿠키 없음 → 401 REFRESH_INVALID")
        }
        
        LocalDateTime now = LocalDateTime.now(clock);

        // incoming rawRefreshRaw를 동일한 방식으로 sha256Hex로 바꿔서 DB에서 조회한다
        RefreshToken old = findByRawForUpdateOrThrow(oldRefreshRaw); // @DisplayName("리프레시: 미발급 refresh 토큰 → 401 REFRESH_INVALID")


        // 1) revoke/reuse 판단 (먼저)
        if (old.isRevoked()) {
            // ROTATED 된 토큰이 다시 제출되면 "재사용 공격/중복제출"로 본다.
            if (old.getRevokeReason() == RefreshRevokeReason.ROTATED) { // @DisplayName("리프레시: 로테이션 후 구 refresh 재사용 → 401 REFRESH_REUSED")
                throw new ApiException(ErrorCode.REFRESH_REUSED);
            }
            // LOGOUT 등 기타 revoke는 그냥 REVOKED로 처리(메시지는 어차피 뭉개도 됨)
            throw new ApiException(ErrorCode.REFRESH_REVOKED); // @DisplayName("refresh: logout으로 revoke된 refresh로 refresh 시도 → 401 REFRESH_REVOKED")
        }

        // 2) 만료
        if (old.isExpired(now)) {
            throw new ApiException(ErrorCode.REFRESH_EXPIRED); // @DisplayName("refresh: expires_at 지난 refresh → 401 REFRESH_EXPIRED")
        }

        // 3) 사용자 조회 (토큰은 유효하지만 DB에 유저가 없으면 refresh도 막는다)
        User user = userRepository.findById(old.getUserId())
                .orElseThrow(() -> new ApiException(ErrorCode.USER_NOT_FOUND)); // @DisplayName("refresh: 로그인 후 유저 삭제(토큰 row도 함께 제거됨) → REFRESH_INVALID")

        // 4) old revoke(ROTATED)
        old.touch(now);
        old.revoke(now, RefreshRevokeReason.ROTATED);


        // 5) new refresh 발급 (rememberMe 계승)
        boolean rememberMe = old.isRememberMe();
        /**
         * @DisplayName("로그인: refresh 쿠키 발급 + DB에는 refresh 해시 저장(rememberMe=false)")
         * @DisplayName("로그인: refresh 쿠키 발급 + DB rememberMe=true 저장(rememberMe=true)")
         * @DisplayName("리프레시: 정상 로테이션(새 refresh 발급) + 기존 refresh ROTATED로 폐기 + 새 row는 revoked=false")
         * @DisplayName("리프레시: 로테이션 후 rememberMe 정책 유지(쿠키 TTL + DB rememberMe 유지)")
         */
        Issued newlyIssued = issue(old.getUserId(), rememberMe); 
        // 6) access 재발급
        String accessToken = jwtService.issueAccessToken(user.getId(), user.getRole());
        
        return new RotateResult(accessToken, newlyIssued.raw(), rememberMe);
    }

    /**
     * 로그아웃/세션 종료 revoke (멱등)
     * - 쿠키 없거나/DB에 없거나/이미 revoked면 그냥 return
     */
    @Transactional
    public void revokeIfPresent(String refreshRaw, RefreshRevokeReason reason) {
        if (refreshRaw == null || refreshRaw.isBlank()) // @DisplayName("logout: 미발급 쿠키 → 204 (idempotent) + 쿠키 삭제(Max-Age=0)")
            return;

        String refreshHash = hashUtils.sha256Hex(refreshRaw);

        // @DisplayName("logout: refresh 쿠키 있음 → DB 토큰 revoke(LOGOUT) + 쿠키 삭제(Max-Age=0)")
        Optional<RefreshToken> opt = refreshTokenRepository.findByTokenHashForUpdate(refreshHash); 
        if (opt.isEmpty())  // @DisplayName("logout: 쿠키 없음 → 204 (idempotent) + 쿠키 삭제 헤더는 내려옴")
            return;

        RefreshToken token = opt.get();
        LocalDateTime now = LocalDateTime.now(clock);

        token.touch(now);
        token.revoke(now, reason); // 멱등
    }

    private RefreshToken findByRawForUpdateOrThrow(String refreshRaw) {
        String hash = hashUtils.sha256Hex(refreshRaw);
        return refreshTokenRepository.findByTokenHashForUpdate(hash)
                    .orElseThrow(() -> new ApiException(ErrorCode.REFRESH_INVALID));
    }


    private long resolveTtlSeconds(boolean rememberMe) {
        return rememberMe
                ? props.refresh().rememberMeSeconds()
                : props.refresh().sessionTtlSeconds();
    }

    public record Issued(String raw, LocalDateTime expiresAt, boolean rememberMe) {}
    public record RotateResult(String accessToken, String newRefreshRaw, boolean rememberMe) {}
}
