package com.kyonggi.backend.auth.identity.signup.service;

import java.time.Clock;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kyonggi.backend.auth.config.OtpProperties;
import com.kyonggi.backend.auth.domain.EmailOtp;
import com.kyonggi.backend.auth.domain.OtpPurpose;
import com.kyonggi.backend.auth.identity.signup.event.SignupOtpIssuedEvent;
import com.kyonggi.backend.auth.identity.signup.support.KyonggiEmailUtils;
import com.kyonggi.backend.auth.identity.signup.support.OtpCodeGenerator;
import com.kyonggi.backend.auth.identity.signup.support.OtpHasher;
import com.kyonggi.backend.auth.repo.EmailOtpRepository;
import com.kyonggi.backend.global.ApiException;
import com.kyonggi.backend.global.ErrorCode;

import lombok.RequiredArgsConstructor;

/**
 * OTP 발급: public void requestSignupOtp(String rawEmail) {...}
 * OTP 검증: public void verifySignupOtp(String rawEmail, String incomingCode) {...}
 * 
 * [테스트 케이스]
 */
@Service
@RequiredArgsConstructor
public class SignupOtpService {

    private static final OtpPurpose PURPOSE = OtpPurpose.SIGNUP;

    private final EmailOtpRepository emailOtpRepository;
    private final ApplicationEventPublisher eventPublisher; // 메일 발송을 "커밋 이후"로 보내기 위한 이벤트 발행자

    private final OtpCodeGenerator otpCodeGenerator;
    private final OtpHasher otpHasher;
    private final OtpProperties props;
    private final Clock clock;

    @Transactional
    public void requestSignupOtp(String rawEmail) {
        // 발송된 이메일 검증 및 정규화
        String email = normalizeKyonggiEmail(rawEmail); // @DisplayName("request: kyonggi 도메인 아니면 → 400 EMAIL_DOMAIN_NOT_ALLOWED")

        LocalDateTime now = LocalDateTime.now(clock);
        LocalDate today = now.toLocalDate();

        //  락 조회: 동시 요청이 정책을 뚫지 못하게 한다.
        EmailOtp otp = emailOtpRepository.findByEmailAndPurposeForUpdate(email, PURPOSE).orElse(null);

        if (otp != null) {
            // 이미 검증 + 미만료면 재요청 막음
            if (otp.isVerified() && !otp.isExpired(now)) {
                throw new ApiException(ErrorCode.OTP_ALREADY_VERIFIED); // @DisplayName("request: 이미 verified + 미만료면 → 400 OTP_ALREADY_VERIFIED")
            }

            // 일일 제한
            int currentCount = otp.getSendCountDate().equals(today) ? otp.getSendCount() : 0;
            if (currentCount >= props.dailySendLimit()) {
                throw new ApiException(ErrorCode.OTP_DAILY_LIMIT); // @DisplayName("request: daily-send-limit 초과 → 429 OTP_DAILY_LIMIT (기본 프로퍼티로)")
            }

            // 쿨다운
            if (otp.getResendAvailableAt().isAfter(now)) {
                long retry = Duration.between(now, otp.getResendAvailableAt()).getSeconds(); // @DisplayName("request: 연속 요청(쿨다운 내) → 429 OTP_COOLDOWN")
                throw new ApiException(
                        ErrorCode.OTP_COOLDOWN,
                        ErrorCode.OTP_COOLDOWN.defaultMessage(),
                        (int) Math.max(retry, 1),
                        null);
            }
        }

        // 새 OTP 생성 (DB에는 해시만)
        String code = otpCodeGenerator.generate6Digits();
        String codeHash = otpHasher.hash(code);

        LocalDateTime expiresAt = now.plusMinutes(props.ttlMinutes());
        LocalDateTime resendAvailableAt = now.plusSeconds(props.resendCooldownSeconds());

        EmailOtp toSave = (otp == null)
                ? EmailOtp.create(email, codeHash, PURPOSE, expiresAt, now, today, resendAvailableAt)
                : reissueAndReturn(otp, codeHash, expiresAt, now, today, resendAvailableAt);

        try {
            /**
             * @DisplayName("request: 정상 → 2xx + 메일로 OTP 발송됨")
             * @DisplayName("request: verified라도 만료된 후면 재발급 가능(2xx)")
             */
            emailOtpRepository.save(toSave);
        } catch (DataIntegrityViolationException e) {
            // 누가 먼저 만들었음 → 다시 락 조회해서 정책대로 처리
            EmailOtp existing = emailOtpRepository.findByEmailAndPurposeForUpdate(email, PURPOSE)
                    .orElseThrow(() -> e);

            // existing 기준으로 쿨다운/일일제한 재검사 후 OTP_COOLDOWN 등 던지기
            LocalDateTime retryAt = existing.getResendAvailableAt();
            long retry = Duration.between(now, retryAt).getSeconds();
            throw new ApiException(
                    ErrorCode.OTP_COOLDOWN,
                    ErrorCode.OTP_COOLDOWN.defaultMessage(),
                    (int) Math.max(retry, 1),
                    null);
        }

        /**
         * 여기서 메일을 직접 보내지 않음.
         * 트랜잭션 커밋이 끝난 후(AFTER_COMMIT) 리스너가 메일을 보낸다.
         */
        eventPublisher.publishEvent(new SignupOtpIssuedEvent(email, code));
    }

    @Transactional(noRollbackFor = OtpInvalidException.class)
    public void verifySignupOtp(String rawEmail, String incomingCode) {
        String email = normalizeKyonggiEmail(rawEmail);
        LocalDateTime now = LocalDateTime.now(clock);

        // 락 조회: 실패횟수 증가/verified 처리에서 레이스 방지
        EmailOtp otpEntity = emailOtpRepository.findByEmailAndPurposeForUpdate(email, PURPOSE)
                .orElseThrow(() -> new ApiException(ErrorCode.OTP_NOT_FOUND)); // @DisplayName("verify: 요청 이력 없으면 → 400 OTP_NOT_FOUND")

        if (otpEntity.isVerified()) { // @DisplayName("verify: 이미 verified면 멱등 성공(2xx) + 실패횟수 증가 없음")
            return; // 멱등
        }

        if (otpEntity.isExpired(now)) {
            throw new ApiException(ErrorCode.OTP_EXPIRED); // @DisplayName("verify: 만료된 OTP → 400 OTP_EXPIRED")
        }

        if (otpEntity.getFailedAttempts() >= props.maxFailures()) {
            throw new ApiException(ErrorCode.OTP_TOO_MANY_FAILURES); // @DisplayName("verify: 실패횟수 초과(>= maxFailures) → 400 OTP_TOO_MANY_FAILURES")
        }

        // 불일치: 실패 횟수 증가 후 예외 (noRollbackFor로 커밋 보장)
        if (!otpHasher.matches(incomingCode, otpEntity.getCodeHash())) { // @DisplayName("verify: 코드 불일치 → 400 OTP_INVALID + failedAttempts가 DB에 +1 커밋됨(noRollbackFor 검증)")
            otpEntity.increaseFailure();     // managed entity 변경 → commit 시 flush로 DB 반영
            throw new OtpInvalidException(); // 예외 던져도 noRollbackFor라 커밋됨 (정책상 실패 횟수를 반드시 남김)
        }

        /**
         * 일치: verified_at 마킹 후 저장
         * JPA의 더티체킹 기능으로, 커밋 시 emailOtpRepository 반영
         */
        otpEntity.markVerified(now); // @DisplayName("verify: 정상 → 2xx + verified=true")
    }

    private EmailOtp reissueAndReturn(
            EmailOtp otpEntity,
            String codeHash,
            LocalDateTime expiresAt,
            LocalDateTime now,
            LocalDate today,
            LocalDateTime resendAvailableAt) {
        otpEntity.reissue(codeHash, expiresAt, now, today, resendAvailableAt);
        return otpEntity;
    }

    private static class OtpInvalidException extends ApiException {
        public OtpInvalidException() {
            super(ErrorCode.OTP_INVALID);
        }
    }

    private String normalizeKyonggiEmail(String rawEmail) {
        KyonggiEmailUtils.validateKyonggiDomain(rawEmail);
        return KyonggiEmailUtils.normalize(rawEmail);
    }
}
