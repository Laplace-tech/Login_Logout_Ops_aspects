package com.kyonggi.backend.auth.service;

import com.kyonggi.backend.auth.config.OtpProperties;
import com.kyonggi.backend.auth.domain.EmailOtp;
import com.kyonggi.backend.auth.domain.OtpPurpose;
import com.kyonggi.backend.auth.repo.EmailOtpRepository;
import com.kyonggi.backend.common.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;

@Service
public class SignupOtpService {

    private static final ZoneId ZONE = ZoneId.of("Asia/Seoul");

    private final EmailOtpRepository emailOtpRepository;
    private final SignupMailSender mailSender;
    private final OtpProperties props;

    public SignupOtpService(EmailOtpRepository emailOtpRepository,
                            SignupMailSender mailSender,
                            OtpProperties props) {
        this.emailOtpRepository = emailOtpRepository;
        this.mailSender = mailSender;
        this.props = props;
    }

    private static String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }

    private static void validateKyonggiEmail(String email) {
        if (!email.endsWith("@kyonggi.ac.kr")) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "EMAIL_DOMAIN_NOT_ALLOWED",
                    "@kyonggi.ac.kr 이메일만 가입할 수 있습니다.");
        }
    }

    @Transactional
    public void requestSignupOtp(String rawEmail) {
        String email = normalizeEmail(rawEmail);
        validateKyonggiEmail(email);

        LocalDateTime now = LocalDateTime.now(ZONE);
        LocalDate today = now.toLocalDate();

        EmailOtp otp = emailOtpRepository.findByEmailAndPurpose(email, OtpPurpose.SIGNUP).orElse(null);

        if (otp != null) {
            // 이미 검증된 상태이고 아직 만료 전이면 재요청 막기(가입 완료로 가게 유도)
            if (otp.isVerified() && !otp.isExpired(now)) {
                throw new ApiException(HttpStatus.CONFLICT, "OTP_ALREADY_VERIFIED",
                        "이미 인증이 완료되었습니다. 회원가입을 완료해주세요.");
            }

            // 쿨다운 체크
            if (otp.getResendAvailableAt().isAfter(now)) {
                int retry = (int) java.time.Duration.between(now, otp.getResendAvailableAt()).getSeconds();
                throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "OTP_COOLDOWN",
                        "잠시 후 다시 시도해주세요.", Math.max(retry, 1));
            }

            // 일일 제한 체크 (날짜 바뀌면 reissue() 안에서 카운트 리셋)
            int currentCount = otp.getSendCountDate().equals(today) ? otp.getSendCount() : 0;
            if (currentCount >= props.dailySendLimit()) {
                throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "OTP_DAILY_LIMIT",
                        "일일 OTP 발송 한도를 초과했습니다. 내일 다시 시도해주세요.");
            }
        }

        String code = OtpCodeGenerator.generate6Digits();
        String codeHash = OtpHasher.hash(code);
        LocalDateTime expiresAt = now.plusMinutes(props.ttlMinutes());
        LocalDateTime resendAvailableAt = now.plusSeconds(props.resendCooldownSeconds());

        if (otp == null) {
            otp = EmailOtp.create(email, codeHash, OtpPurpose.SIGNUP, expiresAt, now, today, resendAvailableAt);
        } else {
            otp.reissue(codeHash, expiresAt, now, today, resendAvailableAt);
        }

        emailOtpRepository.save(otp);
        mailSender.sendOtp(email, code);
    }

    @Transactional
    public void verifySignupOtp(String rawEmail, String code) {
        String email = normalizeEmail(rawEmail);
        validateKyonggiEmail(email);

        LocalDateTime now = LocalDateTime.now(ZONE);

        EmailOtp otp = emailOtpRepository.findByEmailAndPurpose(email, OtpPurpose.SIGNUP)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "OTP_NOT_FOUND",
                        "OTP 요청 이력이 없습니다. 먼저 인증번호를 요청해주세요."));

        if (otp.isExpired(now)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "OTP_EXPIRED", "인증번호가 만료되었습니다. 다시 요청해주세요.");
        }

        if (otp.getFailedAttempts() >= props.maxFailures()) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "OTP_TOO_MANY_FAILURES",
                    "인증 시도 횟수를 초과했습니다. 인증번호를 다시 요청해주세요.");
        }

        // 이미 검증된 경우 idempotent 처리
        if (otp.isVerified()) {
            return;
        }

        if (!OtpHasher.matches(code, otp.getCodeHash())) {
            otp.increaseFailure();
            emailOtpRepository.save(otp);
            throw new ApiException(HttpStatus.BAD_REQUEST, "OTP_INVALID", "인증번호가 올바르지 않습니다.");
        }

        otp.markVerified(now);
        emailOtpRepository.save(otp);
    }
}
