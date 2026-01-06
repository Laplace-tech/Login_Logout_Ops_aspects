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
 * [refresh_tokens 테이블 매핑 엔티티]
 * 
 * 이 엔티티는 "로그인 세션"에 해당한다.
 * - Access Token(JWT)은 서버에 저장하지 않음(Stateless)
 * - Refresh Token은 서버가 통제해야 안전함 -> DB에 "세션"처럼 저장
 * 
 * [보안]
 * - 클라이언트에게는 refresh "raw(원문)"을 쿠키로 내려줌(HttpOnly)
 * - DB에는 raw를 절대 저장하지 않고 token_hash(sha256)만 저장
 *   -> DB가 털려도 raw가 없어서 바로 악용이 어렵게 설계 
 * 
 * [인덱스]
 * @Index: idx_refresh_token_hash 
 *  - token_hash는 조회 키이므로 유니크 인덱스 필수 
 *  - sha256(rawRefresh) -> token_hash로 조회할 것이므로 hash 인덱스 필요)
 * @Index: idx_refresh_user_id 
 *  - user_id는 유저 기준 세션 관리를 위해 인덱스 권장
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
    private Long id; // PK (AUTO_INCREMENT)

    @Column(name = "user_id", nullable = false)
    private Long userId; // 이 refresh 세션이 "누구(user)"의 것인지

    @Column(name = "token_hash", nullable = false, unique = true, length = 64, columnDefinition = "char(64)")
    private String tokenHash; // sha256 hex(64자). raw는 저장 금지!

    @Column(name = "remember_me", nullable = false)
    private boolean rememberMe; // rememberMe=true면 ttl 길게

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt; // 서버가 관리하는 "세션 만료 시각"

    // ========= 아래는 "운영/보안"을 위한 필드들 =============
    
    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    /**
     * String으로 두면 실수/오타가 DB에 들어가서 나중에 복구가 귀찮다.
     * EnumType.STRING이면 컬럼은 문자열이지만 자바 쪽은 enum으로 강제된다.
     * 기존 DB 값이 "ROTATED", "LOGOUT"이면 그대로 매핑된다(마이그레이션 불필요).
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
     * RefreshTokenService.issue()
     * - raw 생성
     * - hash 저장
     * - DB row 생성 
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
        if (now == null) throw new IllegalArgumentException("now must not be null");

        RefreshToken rt = new RefreshToken();
        rt.userId = userId;
        rt.tokenHash = tokenHash;
        rt.rememberMe = rememberMe;
        rt.expiresAt = expiresAt;
        rt.createdAt = now;
        return rt;
    }

    public boolean isExpired(LocalDateTime now) {
        return !expiresAt.isAfter(now);
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public void revoke(LocalDateTime now, RefreshRevokeReason reason) {
        if (this.revokedAt != null) return;
        this.revokedAt = now;
        this.revokeReason = reason;
    }

    public void touch(LocalDateTime now) {
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
