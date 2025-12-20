package com.kyonggi.backend.auth.service;

import com.kyonggi.backend.auth.domain.EmailOtp;
import com.kyonggi.backend.auth.domain.OtpPurpose;
import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.repo.EmailOtpRepository;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.common.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;

@Service
public class SignupService {

    private static final ZoneId ZONE = ZoneId.of("Asia/Seoul");
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private final EmailOtpRepository emailOtpRepository;
    private final UserRepository userRepository;

    public SignupService(EmailOtpRepository emailOtpRepository, UserRepository userRepository) {
        this.emailOtpRepository = emailOtpRepository;
        this.userRepository = userRepository;
    }

    private static String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }

    @Transactional
    public void completeSignup(String rawEmail, String rawPassword, String nickname) {
        String email = normalizeEmail(rawEmail);
        LocalDateTime now = LocalDateTime.now(ZONE);

        EmailOtp otp = emailOtpRepository.findByEmailAndPurpose(email, OtpPurpose.SIGNUP)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "OTP_NOT_FOUND",
                        "OTP 인증이 필요합니다."));

        if (!otp.isVerified()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "OTP_NOT_VERIFIED", "OTP 인증을 먼저 완료해주세요.");
        }

        // 정책 단순화: OTP TTL(5분) 안에 가입 완료까지 해야 함
        if (otp.getExpiresAt().isBefore(now)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "OTP_EXPIRED", "인증이 만료되었습니다. 다시 인증해주세요.");
        }

        if (userRepository.existsByEmail(email)) {
            throw new ApiException(HttpStatus.CONFLICT, "EMAIL_ALREADY_EXISTS", "이미 가입된 이메일입니다.");
        }

        if (userRepository.existsByNickname(nickname)) {
            throw new ApiException(HttpStatus.CONFLICT, "NICKNAME_ALREADY_EXISTS", "이미 사용 중인 닉네임입니다.");
        }

        if (rawPassword == null || rawPassword.length() < 8) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "WEAK_PASSWORD", "비밀번호는 8자 이상이어야 합니다.");
        }

        String passwordHash = passwordEncoder.encode(rawPassword);
        userRepository.save(User.create(email, passwordHash, nickname));

        // 재사용 방지: OTP 만료 처리(또는 delete해도 됨)
        otp.markVerified(now); // verified_at 업데이트(이미 verified지만 명시)
        // expires_at을 now로 줄이려면 엔티티에 setter 만들기보다 delete 추천
        emailOtpRepository.delete(otp);
    }
}
