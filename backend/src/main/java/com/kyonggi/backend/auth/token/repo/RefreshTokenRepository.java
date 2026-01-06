package com.kyonggi.backend.auth.token.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.kyonggi.backend.auth.token.domain.RefreshToken;

import jakarta.persistence.LockModeType;

/**
 * RefreshToken 저장소
 * 
 * - rotate는 동일 refreshRaw가 동시에 2번 들어오는 케이스를 반드시 막아야 한다.
 *   그래서 token_hash 기준으로 row를 잠그는 조회(SELECT ... FOR UPDATE)가 필요하다.
 */
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from RefreshToken r where r.tokenHash = :tokenHash")
    Optional<RefreshToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);
}
