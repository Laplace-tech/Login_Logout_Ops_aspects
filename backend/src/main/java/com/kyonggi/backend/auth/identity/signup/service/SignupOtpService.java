package com.kyonggi.backend.auth.identity.signup.service;

import java.time.Clock;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kyonggi.backend.auth.config.OtpProperties;
import com.kyonggi.backend.auth.domain.EmailOtp;
import com.kyonggi.backend.auth.domain.OtpPurpose;
import com.kyonggi.backend.auth.identity.signup.support.KyonggiEmailUtils;
import com.kyonggi.backend.auth.identity.signup.support.OtpCodeGenerator;
import com.kyonggi.backend.auth.identity.signup.support.OtpHasher;
import com.kyonggi.backend.auth.repo.EmailOtpRepository;
import com.kyonggi.backend.global.ApiException;
import com.kyonggi.backend.global.ErrorCode;

import lombok.RequiredArgsConstructor;

/**
 * 회원가입 OTP 유스케이스
 *
 * 설계 포인트
 * - (email, purpose) 당 OTP 1개(유니크)만 유지
 * - 재요청: 쿨다운 / 일일 제한 / 이미 검증된 상태면 막기
 * - 검증 실패 시 failedAttempts 증가를 DB에 "반드시" 남겨야 하므로
 *   OtpInvalidException만 noRollbackFor로 커밋되게 처리
 */
@Service
@RequiredArgsConstructor
public class SignupOtpService {

    private static final OtpPurpose PURPOSE = OtpPurpose.SIGNUP;

    private final EmailOtpRepository emailOtpRepository;
    private final SignupMailSender mailSender;

    private final OtpCodeGenerator otpCodeGenerator;
    private final OtpHasher otpHasher;
    private final OtpProperties props;
    private final Clock clock;

    @Transactional
    public void requestSignupOtp(String rawEmail) {
        // 유틸에서 normalize + domain validation 안전하게
        KyonggiEmailUtils.validateKyonggiDomain(rawEmail);
        String email = KyonggiEmailUtils.normalize(rawEmail);

        LocalDateTime now = LocalDateTime.now(clock);
        LocalDate today = now.toLocalDate();

        EmailOtp otp = emailOtpRepository.findByEmailAndPurpose(email, PURPOSE).orElse(null);

        if (otp != null) {
            // 1) 이미 검증 + 미만료면 “재요청” 막고 complete 유도
            if (otp.isVerified() && !otp.isExpired(now)) {
                throw new ApiException(ErrorCode.OTP_ALREADY_VERIFIED);
            }

            // 2) 쿨다운
            if (otp.getResendAvailableAt().isAfter(now)) {
                long retry = Duration.between(now, otp.getResendAvailableAt()).getSeconds();
                throw new ApiException(
                        ErrorCode.OTP_COOLDOWN,
                        ErrorCode.OTP_COOLDOWN.defaultMessage(),
                        (int) Math.max(retry, 1),
                        null
                );
            }

            // 3) 일일 제한
            int currentCount = otp.getSendCountDate().equals(today) ? otp.getSendCount() : 0;
            if (currentCount >= props.dailySendLimit()) {
                throw new ApiException(ErrorCode.OTP_DAILY_LIMIT);
            }
        }

        // 새 OTP 생성(원문은 메일로만 보내고, DB엔 해시만 저장)
        String code = otpCodeGenerator.generate6Digits();
        String codeHash = otpHasher.hash(code);

        LocalDateTime expiresAt = now.plusMinutes(props.ttlMinutes());
        LocalDateTime resendAvailableAt = now.plusSeconds(props.resendCooldownSeconds());

        EmailOtp toSave = (otp == null)
                ? EmailOtp.create(email, codeHash, PURPOSE, expiresAt, now, today, resendAvailableAt)
                : reissueAndReturn(otp, codeHash, expiresAt, now, today, resendAvailableAt);

        emailOtpRepository.save(toSave);
        mailSender.sendOtp(email, code);
    }

    @Transactional(noRollbackFor = OtpInvalidException.class)
    public void verifySignupOtp(String rawEmail, String incomingCode) {
        KyonggiEmailUtils.validateKyonggiDomain(rawEmail);
        String email = KyonggiEmailUtils.normalize(rawEmail);

        LocalDateTime now = LocalDateTime.now(clock);

        EmailOtp otpEntity = emailOtpRepository.findByEmailAndPurpose(email, PURPOSE)
                .orElseThrow(() -> new ApiException(ErrorCode.OTP_NOT_FOUND));

        // 이미 인증된 상태면 멱등 처리(idempotent)로 그냥 성공 처리
        if (otpEntity.isVerified()) {
            return;
        }

        if (otpEntity.isExpired(now)) {
            throw new ApiException(ErrorCode.OTP_EXPIRED);
        }

        if (otpEntity.getFailedAttempts() >= props.maxFailures()) {
            throw new ApiException(ErrorCode.OTP_TOO_MANY_FAILURES);
        }

        // 불일치: 실패 횟수 증가 후 예외 (noRollbackFor로 커밋 보장)
        if (!otpHasher.matches(incomingCode, otpEntity.getCodeHash())) {
            otpEntity.increaseFailure();
            emailOtpRepository.save(otpEntity);
            throw new OtpInvalidException();
        }

        // 일치: verified_at 마킹 후 저장
        otpEntity.markVerified(now);
        emailOtpRepository.save(otpEntity);
    }

    private EmailOtp reissueAndReturn(
            EmailOtp otpEntity,
            String codeHash,
            LocalDateTime expiresAt,
            LocalDateTime now,
            LocalDate today,
            LocalDateTime resendAvailableAt
    ) {
        otpEntity.reissue(codeHash, expiresAt, now, today, resendAvailableAt);
        return otpEntity;
    }

    private static class OtpInvalidException extends ApiException {
        public OtpInvalidException() {
            super(ErrorCode.OTP_INVALID);
        }
    }
}
