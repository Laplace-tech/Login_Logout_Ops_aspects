package com.kyonggi.backend.auth.signup.service;

import java.time.Clock;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kyonggi.backend.auth.config.OtpProperties;
import com.kyonggi.backend.auth.domain.EmailOtp;
import com.kyonggi.backend.auth.domain.OtpPurpose;
import com.kyonggi.backend.auth.repo.EmailOtpRepository;
import com.kyonggi.backend.auth.signup.support.KyonggiEmailUtils;
import com.kyonggi.backend.auth.signup.support.OtpCodeGenerator;
import com.kyonggi.backend.auth.signup.support.OtpHasher;
import com.kyonggi.backend.common.ApiException;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SignupOtpService {

    private final EmailOtpRepository emailOtpRepository;
    private final SignupMailSender mailSender;

    private final OtpCodeGenerator otpCodeGenerator;
    private final OtpHasher otpHasher;
    private final OtpProperties props;
    private final Clock clock;

    @Transactional
    public void requestSignupOtp(String rawEmail) {
        String email = KyonggiEmailUtils.normalizeEmail(rawEmail);
        KyonggiEmailUtils.validateDomain(email);

        LocalDateTime now = LocalDateTime.now(clock);
        LocalDate today = now.toLocalDate();

        EmailOtp otp = emailOtpRepository.findByEmailAndPurpose(email, OtpPurpose.SIGNUP).orElse(null);

        if (otp != null) {
            // 1) 이미 검증 + 미만료면 재요청 금지 (complete로 유도)
            if (otp.isVerified() && !otp.isExpired(now)) {
                throw new ApiException(
                        HttpStatus.CONFLICT,
                        "OTP_ALREADY_VERIFIED",
                        "이미 인증이 완료되었습니다. 회원가입을 완료해주세요."
                );
            }

            // 2) 쿨다운
            if (otp.getResendAvailableAt() != null && otp.getResendAvailableAt().isAfter(now)) {
                long retry = Duration.between(now, otp.getResendAvailableAt()).getSeconds();
                throw new ApiException(
                        HttpStatus.TOO_MANY_REQUESTS,
                        "OTP_COOLDOWN",
                        "잠시 후 다시 시도해주세요.",
                        (int) Math.max(retry, 1)
                );
            }

            // 3) 일일 제한
            int currentCount = (otp.getSendCountDate() != null && otp.getSendCountDate().equals(today))
                    ? otp.getSendCount()
                    : 0;

            if (currentCount >= props.dailySendLimit()) {
                throw new ApiException(
                        HttpStatus.TOO_MANY_REQUESTS,
                        "OTP_DAILY_LIMIT",
                        "일일 OTP 발송 한도를 초과했습니다. 내일 다시 시도해주세요."
                );
            }
        }

        String code = otpCodeGenerator.generate6Digits();
        String codeHash = otpHasher.hash(code);

        LocalDateTime expiresAt = now.plusMinutes(props.ttlMinutes());
        LocalDateTime resendAvailableAt = now.plusSeconds(props.resendCooldownSeconds());

        if (otp == null) {
            otp = EmailOtp.create(
                    email,
                    codeHash,
                    OtpPurpose.SIGNUP,
                    expiresAt,
                    now,
                    today,
                    resendAvailableAt
            );
        } else {
            otp.reissue(codeHash, expiresAt, now, today, resendAvailableAt);
        }

        emailOtpRepository.save(otp);
        mailSender.sendOtp(email, code);
    }

    @Transactional
    public void verifySignupOtp(String rawEmail, String code) {
        String email = KyonggiEmailUtils.normalizeEmail(rawEmail);
        KyonggiEmailUtils.validateDomain(email);

        LocalDateTime now = LocalDateTime.now(clock);

        EmailOtp otp = emailOtpRepository.findByEmailAndPurpose(email, OtpPurpose.SIGNUP)
                .orElseThrow(() -> new ApiException(
                        HttpStatus.BAD_REQUEST,
                        "OTP_NOT_FOUND",
                        "OTP 요청 이력이 없습니다. 먼저 인증번호를 요청해주세요."
                ));

        // ✅ 이미 검증된 경우 idempotent
        if (otp.isVerified()) {
            return;
        }

        if (otp.isExpired(now)) {
            throw new ApiException(
                    HttpStatus.BAD_REQUEST,
                    "OTP_EXPIRED",
                    "인증번호가 만료되었습니다. 다시 요청해주세요."
            );
        }

        if (otp.getFailedAttempts() >= props.maxFailures()) {
            throw new ApiException(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "OTP_TOO_MANY_FAILURES",
                    "인증 시도 횟수를 초과했습니다. 인증번호를 다시 요청해주세요."
            );
        }

        if (!otpHasher.matches(code, otp.getCodeHash())) {
            otp.increaseFailure();
            emailOtpRepository.save(otp);
            throw new ApiException(
                    HttpStatus.BAD_REQUEST,
                    "OTP_INVALID",
                    "인증번호가 올바르지 않습니다."
            );
        }

        otp.markVerified(now);
        emailOtpRepository.save(otp);
    }
}
