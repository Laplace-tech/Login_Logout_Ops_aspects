package com.kyonggi.backend.auth.token.domain;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * refresh_tokens 테이블 매핑 엔티티 (서버가 관리하는 로그인 세션)
 * 
 * 이 엔티티는 "로그인 세션"에 해당한다.
 * - Access Token(JWT)은 서버에 저장하지 않음(Stateless)
 * - Refresh Token은 서버가 DB로 상태 관리
 * 
 * 핵심 보안 불변 조건(invariants):
 * 
 * 1) refresh raw(원문)은 DB에 절대 저장하지 않는다. (token_hash만 저장)
 * 2) rotated 시 기존에 발행된 토큰은 ROTATED로 revoke된다.
 * 3) ROTATED 된 토큰이 다시 제출되면 "재사용 공격"으로 보고 차단한다 (REFRESH_REUSED)
 * 
 * 인덱스:
 * @Index: idx_refresh_token_hash 
 *  - token_hash: 쿠키에서 refresh 토큰 원문을 추출한 뒤 해싱한 값
 *  - 해싱된 문자열이 곧 DB에서 쓸 조회 키이므로 유니크 인덱스 필수 
 * @Index: idx_refresh_user_id 
 *  - user_id: 유저 단위 세션 관리/정리용 인덱스 권장
 */
@Getter
@Entity
@Table(name = "refresh_tokens", indexes = {
    @Index(name = "idx_refresh_token_hash", columnList = "token_hash", unique = true),
    @Index(name = "idx_refresh_user_id", columnList = "user_id")
})
@NoArgsConstructor(access=AccessLevel.PROTECTED) // JPA가 리플렉션으로 객체 생성
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId; 

    // sha256 hex(64자), raw는 저장 금지
    @Column(name = "token_hash", nullable = false, unique = true, length = 64, columnDefinition = "char(64)")
    private String tokenHash;

    @Column(name = "remember_me", nullable = false)
    private boolean rememberMe;

    // 서버가 관리하는 "세션 만료 시각"
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;


    // ========= 아래는 "운영/보안"을 위한 필드들 =============
    
    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    /**
     * EnumType.STRING: 컬럼은 문자열이지만 자바 쪽은 enum으로 강제된다.
     * 기존 DB 값이 "ROTATED", "LOGOUT"이면 그대로 매핑된다.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "revoke_reason", length = 50)
    private RefreshRevokeReason revokeReason;

    @Column(name = "user_agent", length = 255)
    private String userAgent;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;


    /**
     * 발급 팩토리 메서드 (RefreshTokenService 에서 호출됨)
     * RefreshTokenService.issue():
     */
    public static RefreshToken issue(
            Long userId, 
            String tokenHash, 
            boolean rememberMe,
            LocalDateTime now,
            LocalDateTime expiresAt
    ) {
        if (userId == null) throw new IllegalArgumentException("userId must not be null");
        if (tokenHash == null || tokenHash.isBlank()) throw new IllegalArgumentException("tokenHash must not be blank");
        if (expiresAt == null) throw new IllegalArgumentException("expiresAt must not be null");
        if (!expiresAt.isAfter(now)) throw new IllegalArgumentException("expiresAt must be after now");
        if (now == null) throw new IllegalArgumentException("now must not be null");

        RefreshToken rt = new RefreshToken();
        rt.userId = userId;
        rt.tokenHash = tokenHash;
        rt.rememberMe = rememberMe;
        rt.createdAt = now;
        rt.expiresAt = expiresAt;
        return rt;
    }

    // -------------
    // domain method
    // -------------

    public boolean isExpired(LocalDateTime now) {
        return !expiresAt.isAfter(now);
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isRotated() {
        return isRevoked() && revokeReason == RefreshRevokeReason.ROTATED;
    }

    // revoke: 멱등 (이미 revoked면 상태 변경 없음)
    public void revoke(LocalDateTime now, RefreshRevokeReason reason) {
        if (now == null) throw new IllegalArgumentException("now must not be null");
        if (reason == null) throw new IllegalArgumentException("reason must not be null");

        if (this.revokedAt != null) return;
        this.revokedAt = now;
        this.revokeReason = reason;
    }

    public void touch(LocalDateTime now) {
        if (now == null) throw new IllegalArgumentException("now must not be null");
        this.lastUsedAt = now;
    }

    /**
     * 선택: 발급 시점에 클라이언트 정보를 기록하고 싶을 때 사용.
     * (지금 컨트롤러/서비스 설계상 request 정보를 안 받고 있어서, 훗날 확장용으로만 둠)
     */
    public void recordClientInfo(String userAgent, String ipAddress) {
        this.userAgent = userAgent;
        this.ipAddress = ipAddress;
    }
}
