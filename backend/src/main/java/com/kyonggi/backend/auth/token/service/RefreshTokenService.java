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
 * Refresh Token 발급 서비스
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
 * - rememberMe=false → 짧은 TTL(1d 같은) + 쿠키는 세션 쿠키(브라우저 종료 시 삭제) 
 */

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository repo;   // refresh_tokens 테이블 저장/조회
    private final UserRepository userRepository;
    private final JwtService jwtService;

    private final TokenGenerator tokenGenerator; // 랜덤 refresh raw 생성(SecureRandom)
    private final TokenHashUtils hashUtils;      // raw -> sha256Hex(hash) 변환

    private final AuthProperties props;       
    private final Clock clock;                 

    /**
     * Refresh Token 발급: "토큰 발급" + "DB 저장"이 한 단위의 유스케이스로 같이 성공/실패 해야 함
     * - raw 생성 -> sha256Hex로 해싱 -> DB 저장
     * - 클라이언트에는 raw를 쿠키로 내려줘야 하므로 raw를 반환한다.
     */
    @Transactional
    public Issued issue(Long userId, boolean rememberMe) {
        if (userId == null) {
            throw new IllegalArgumentException("userId must not be null");
        }

        LocalDateTime now = LocalDateTime.now(clock); // now 구하기
        long ttlSeconds = resolveTtlSeconds(rememberMe); // rememberMe 여부에 따라 TTL 결정 (초 단위) 
        LocalDateTime expiresAt = now.plusSeconds(ttlSeconds); // 만료 시각 계산 = now + TTL

        String raw = tokenGenerator.generateRefreshToken(); // refresh 토큰 원문 생성
        String hash = hashUtils.sha256Hex(raw); // 원문 해싱
        

        // "토큰 발급" + "DB 저장"
        repo.save(RefreshToken.issue(userId, hash, rememberMe, now, expiresAt));
        return new Issued(raw, expiresAt, rememberMe); // 컨트롤러가 쿠키로 내려주기 위해 raw를 반환
    }

    /**
     * Refresh Token "회전(재발급)" 유스케이스
     * - old refresh를 검증/폐기(revoke)
     * - new refresh를 발급/저장
     * - 새 access token 발급
     */
    @Transactional
    public RotateResult rotate(String oldRefreshRaw) {
        if (oldRefreshRaw == null || oldRefreshRaw.isBlank()) {
            throw new ApiException(ErrorCode.REFRESH_INVALID);
        }
        
        LocalDateTime now = LocalDateTime.now(clock);

        // incoming rawRefreshRaw를 동일한 방식으로 sha256Hex로 바꿔서 DB에서 조회한다
        RefreshToken old = findByRawOrThrow(oldRefreshRaw);


        // 1) 재사용(폐기된 토큰 재제출) 감지 우선
        if (old.isRevoked()) {
            throw new ApiException(ErrorCode.REFRESH_REUSED); // 메시지 뭉개기 OK
        }

        // 2) 만료
        if (old.isExpired(now)) {
            throw new ApiException(ErrorCode.REFRESH_EXPIRED);
        }

        // 3) 정상 rotation: old 폐기 + 감사 필드 업데이트
        old.touch(now);
        old.revoke(now, RefreshRevokeReason.ROTATED.name());
        // ✅ save 호출 안 해도 됨 (JPA dirty checking). 단, old는 영속 상태여야 함.
        // findByTokenHash로 가져온 엔티티면 영속 상태라 커밋 시 반영된다.


        // 4) new refresh 발급(rememberMe 정책은 old를 계승)
        boolean rememberMe = old.isRememberMe();
        Issued newlyIssued = this.issue(old.getUserId(), rememberMe); // 새 리프레쉬 토큰 발급받음

        // 5) 사용자 조회 + 상태 정책 체크(실무적으로 여기서 ACTIVE만 허용 같은 정책 들어감)
        User user = userRepository.findById(old.getUserId())
                .orElseThrow(() -> new ApiException(ErrorCode.USER_NOT_FOUND));

        // 6) accessToken 새로 발급
        String accessToken = jwtService.issueAccessToken(user.getId(), user.getRole().name());
        return new RotateResult(accessToken, newlyIssued.raw(), rememberMe);
    }

    /**
     * 로그아웃/세션종료용 revoke (멱등)
     * - 쿠키 없거나/DB에 없거나/이미 revoked여도 그냥 return
     */
    @Transactional
    public void revokeIfPresent(String refreshRaw, String reason) {
        if(refreshRaw == null || refreshRaw.isBlank()) 
            return;

        String refreshHash = hashUtils.sha256Hex(refreshRaw);
        Optional<RefreshToken> opt = repo.findByTokenHash(refreshHash);
        if (opt.isEmpty()) 
            return;

        RefreshToken token = opt.get();
        if (token.isRevoked()) 
            return;

        LocalDateTime now = LocalDateTime.now(clock);
        token.touch(now);              // ✅ 실무에선 보통 남김(감사/추적)
        token.revoke(now, reason);     // ✅ dirty checking
    }

    private RefreshToken findByRawOrThrow(String refreshRaw) {
        String hash = hashUtils.sha256Hex(refreshRaw);
        return repo.findByTokenHash(hash)
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
