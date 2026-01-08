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
 * [rotate 동시성 방어]:
 * - 동일 refreshRaw(=동일 token_hash)가 동시에 2번 들어와서 둘 다 성공하는 순간 보안이 깨진다.
 * - 그래서 rotate에서 기존의 old 토큰 row를 반드시 row-lock으로 잡고 처리한다.
 *   :(PESSIMISTIC_WRITE = SELECT .. FOR UPDATE)
 */
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * LockModeType.PESSIMISTIC_WRITE:
     * - 데이터를 건드리는 동안, 다른 트랜잭션이 DB를 건드리지 못하게 막음.
     *   해당 트랜잭션이 끝나기 전까지, 다른 트랜잭션은 해당 Row를 읽지도 수정하지도 못하고 대기(Wait)해야 한다.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from RefreshToken r where r.tokenHash = :tokenHash")
    Optional<RefreshToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);
}
