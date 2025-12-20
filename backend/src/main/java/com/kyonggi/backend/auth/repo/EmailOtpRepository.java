package com.kyonggi.backend.auth.repo;

import com.kyonggi.backend.auth.domain.EmailOtp;
import com.kyonggi.backend.auth.domain.OtpPurpose;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EmailOtpRepository extends JpaRepository<EmailOtp, Long> {
    Optional<EmailOtp> findByEmailAndPurpose(String email, OtpPurpose purpose);
}
