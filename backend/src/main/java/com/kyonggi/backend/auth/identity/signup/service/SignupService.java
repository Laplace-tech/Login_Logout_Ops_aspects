package com.kyonggi.backend.auth.identity.signup.service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.regex.Pattern;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kyonggi.backend.auth.domain.EmailOtp;
import com.kyonggi.backend.auth.domain.OtpPurpose;
import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.identity.signup.support.KyonggiEmailUtils;
import com.kyonggi.backend.auth.identity.signup.support.SignupPatterns;
import com.kyonggi.backend.auth.repo.EmailOtpRepository;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.global.ApiException;
import com.kyonggi.backend.global.ErrorCode;

import lombok.RequiredArgsConstructor;

/**
 * OTP 인증이 끝난 사용자를 실제 User로 전환하는 경계 서비스
 * - OTP 검증 결과를 신뢰
 * - User 중복/정책만 확인
 * - 계정 생성 후 OTP 제거
 */
@Service
@RequiredArgsConstructor
public class SignupService {

    private final EmailOtpRepository emailOtpRepository;
    private final UserRepository userRepository;

    private final Clock clock;
    private final PasswordEncoder passwordEncoder;

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(SignupPatterns.PASSWORD_REGEX);
    private static final Pattern NICKNAME_PATTERN = Pattern.compile(SignupPatterns.NICKNAME_REGEX);

    @Transactional
    public void completeSignup(String rawEmail, String rawPassword, String rawPasswordConfirm, String nickname) {
        KyonggiEmailUtils.validateKyonggiDomain(rawEmail);
        String email = KyonggiEmailUtils.normalize(rawEmail);

        LocalDateTime now = LocalDateTime.now(clock);

        // 비밀번호 일치 검사
        if (rawPassword == null || rawPasswordConfirm == null || !rawPassword.equals(rawPasswordConfirm)) {
            throw new ApiException(ErrorCode.PASSWORD_MISMATCH);
        }

        // 서비스 정책 검증
        if (!PASSWORD_PATTERN.matcher(rawPassword).matches()) {
            throw new ApiException(ErrorCode.WEAK_PASSWORD);
        }

        String nick = nickname == null ? "" : nickname.trim();
        if (!NICKNAME_PATTERN.matcher(nick).matches()) {
            throw new ApiException(ErrorCode.INVALID_NICKNAME);
        }

        // 해당 이메일이 OTP 레코드에 있는지 검사 -> 없으면 OTP 인증 필요
        EmailOtp otp = emailOtpRepository.findByEmailAndPurpose(email, OtpPurpose.SIGNUP)
                .orElseThrow(() -> new ApiException(ErrorCode.OTP_NOT_FOUND));

        // OTP 인증 미완료
        if (!otp.isVerified()) {
            throw new ApiException(ErrorCode.OTP_NOT_VERIFIED);
        }

        // OTP 인증 만료, 재인증 필요(reissue)
        if (otp.getExpiresAt().isBefore(now)) {
            throw new ApiException(ErrorCode.OTP_EXPIRED);
        }

        // 이메일 중복성 검사
        if (userRepository.existsByEmail(email)) {
            throw new ApiException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }

        // 닉네임 중복성 검사
        if (userRepository.existsByNickname(nick)) {
            throw new ApiException(ErrorCode.NICKNAME_ALREADY_EXISTS);
        }

        String passwordHash = passwordEncoder.encode(rawPassword);
        userRepository.save(User.create(email, passwordHash, nick));

        // 재사용 방지: OTP 레코드 제거
        emailOtpRepository.delete(otp);
    }
}
