package com.kyonggi.backend.auth.token.service;

import java.time.Clock;
import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kyonggi.backend.auth.config.AuthProperties;
import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.auth.security.JwtService;
import com.kyonggi.backend.auth.token.domain.RefreshToken;
import com.kyonggi.backend.auth.token.repo.RefreshTokenRepository;
import com.kyonggi.backend.auth.token.support.TokenGenerator;
import com.kyonggi.backend.auth.token.support.TokenHashUtils;
import com.kyonggi.backend.common.ApiException;

import lombok.RequiredArgsConstructor;

/**
 * ========================
 * Refresh Token 발급 서비스
 * ========================
 * 
 * Refresh Token: 
 * - Access Token의 TTL이 만료됐을 때 "재로그인 없이" Access Token을 다시 받기 위한 토큰
 * - Access Token 보다 TTL이 길다 (rememberMe면 더 길게)
 * 
 * 왜 DB에 저장하나?
 * - Access Token은 stateless(JWT)라 서버가 저장 안 함
 * - Refresh Token은 "세션처럼" 서버가 통제해야 안전함
 * 
 * 왜 원문(raw)을 DB에 저장하지 않나?
 * - DB가 털리면 raw가 그대로 악용됨
 * - 그래서 DB에는 sha256 해시만 저장
 *  (검증 시, incoming raw -> sha256 -> DB hash 비교)
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
     * Refresh Token 발급: 토큰 발급 + DB 저장이 한 단위의 유스케이스로 같이 성공/실패 해야 함
     */
    @Transactional
    public Issued issue(Long userId, boolean rememberMe) {
        LocalDateTime now = LocalDateTime.now(clock); // now 구하기

        // rememberMe 여부에 따라 TTL 결정 (초 단위)
        long ttlSeconds = rememberMe 
            ? props.refresh().rememberMeSeconds() 
            : props.refresh().sessionTtlSeconds();

        LocalDateTime expiresAt = now.plusSeconds(ttlSeconds); // 만료 시각 계산 = now + TTL

        /**
         * raw refresh 토큰 생성 -> sha256 으로 해싱 -> 디비 저장
         * (검증 시, incoming raw -> sha256 해싱 -> 디비 값과 비교)
         */
        String rawRefresh = tokenGenerator.generateRefreshToken(); // refresh 토큰 생성
        String hash = hashUtils.sha256Hex(rawRefresh);
        
        repo.save(RefreshToken.issue(userId, hash, rememberMe, now, expiresAt));
        return new Issued(rawRefresh, expiresAt, rememberMe); // 컨트롤러가 쿠키로 내려주기 위해 raw를 반환
    }

    /**
     * refresh rotation (재발급/회전)
     * - "old refresh"는 즉시 폐기(revoke)
     * - "new refresh"를 새로 발급하고 저장
     * - access token 재발급해서 반환
     */
    @Transactional
    public RotateResult rotate(String oldRefreshRaw) {
        LocalDateTime now = LocalDateTime.now(clock);
        
        String oldRefreshHash = hashUtils.sha256Hex(oldRefreshRaw); // 요청으로 들어온 refresh raw를 동일하게 해싱해서 DB 조회

        RefreshToken old = repo.findByTokenHash(oldRefreshHash)
                .orElseThrow(() -> new ApiException(
                    HttpStatus.UNAUTHORIZED, // 401 UNAUTHORIZED
                    "REFRESH_INVALID", 
                    "리프레시 토큰이 유효하지 않습니다."
                ));
    
        // 만료 검사
        if (old.isExpired(now)) {
            throw new ApiException(
                HttpStatus.UNAUTHORIZED, 
                "REFRESH_EXPIRED", 
                "리프레시 토큰이 만료되었습니다.");
        }

        // 이미 폐기된 토큰이면 "재사용"으로 판단
        if(old.isRevoked()) {
            throw new ApiException(
                HttpStatus.UNAUTHORIZED, 
                "REFRESH_REUSED", 
                "리프레시 토큰이 이미 폐기되었습니다."
            );
        }

        // old revoke
        old.touch(now); // last_used_at 업데이트(감사/추적)
        old.revoke(now, "ROTATED");  // revoked_at + revoke_reason 기록
        repo.save(old);


        // new refresh token issue (rememberMe는 old 값을 그대로 계승)
        boolean rememberMe = old.isRememberMe();
        long ttlSeconds = rememberMe 
            ? props.refresh().rememberMeSeconds()
            : props.refresh().sessionTtlSeconds();

        LocalDateTime newExpiresAt = now.plusSeconds(ttlSeconds);
        String newRaw = tokenGenerator.generateRefreshToken();
        String newHash = hashUtils.sha256Hex(newRaw);

        repo.save(RefreshToken.issue(old.getUserId(), newHash, rememberMe, now, newExpiresAt));
        
        User user = userRepository.findById(old.getUserId())
            .orElseThrow(() -> new ApiException(
                HttpStatus.UNAUTHORIZED,
                "USER_NOT_FOUND",
                "사용자를 찾을 수 없습니다."));
        
        // accessToken 새로 발급
        String accessToken = jwtService.issueAccessToken(user.getId(), user.getRole().name());
        return new RotateResult(accessToken, newRaw, rememberMe);
    }

    public record Issued(String raw, LocalDateTime expiresAt, boolean rememberMe) {}
    public record RotateResult(String accessToken, String newRefreshRaw, boolean rememberMe) {}
}
