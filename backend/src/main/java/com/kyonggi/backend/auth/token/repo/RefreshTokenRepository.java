package com.kyonggi.backend.auth.token.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.kyonggi.backend.auth.token.domain.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);
}
