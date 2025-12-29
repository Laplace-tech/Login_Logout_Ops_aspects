package com.kyonggi.backend.auth.token.domain;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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
 * - 클라이언트에게는 refresh "raw(원문)"을 쿠키로 내려줌(HttpOnly)
 * - DB에는 raw를 절대 저장하지 않고 token_hash(sha256)만 저장
 *   -> DB가 털려도 raw가 없어서 바로 악용이 어렵게 설계 
 * 
 * @Index: idx_refresh_token_hash (raw -> sha256 -> token_hash로 조회할 것이므로 hash 인덱스 필요)
 * @Index: idx_refresh_user_id (유저 기준 조회를 위한 user_id 인덱스)
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

    @Column(name = "revoke_reason", length = 50)
    private String revokeReason;

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
    public static RefreshToken issue(Long userId, String tokenHash, boolean rememberMe,
                                    LocalDateTime now, LocalDateTime expiresAt) {
        RefreshToken rt = new RefreshToken();
        rt.userId = userId;
        rt.tokenHash = tokenHash;
        rt.rememberMe = rememberMe;
        rt.expiresAt = expiresAt;
        rt.createdAt = now;
        return rt;
    }

    public boolean isExpired(LocalDateTime now) {return !expiresAt.isAfter(now);}
    public boolean isRevoked() {return revokedAt != null;}
    public void revoke(LocalDateTime now, String reason) {
        this.revokedAt = now;
        this.revokeReason = reason;
    }
    public void touch(LocalDateTime now) {
        this.lastUsedAt = now;
    }
}
