package com.kyonggi.backend.auth.service;

import com.kyonggi.backend.auth.config.OtpProperties;
import com.kyonggi.backend.auth.domain.EmailOtp;
import com.kyonggi.backend.auth.domain.OtpPurpose;
import com.kyonggi.backend.auth.repo.EmailOtpRepository;
import com.kyonggi.backend.auth.support.KyonggiEmailUtils;
import com.kyonggi.backend.common.ApiException;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class SignupOtpService {

    private final EmailOtpRepository emailOtpRepository;
    private final SignupMailSender mailSender;

    private final OtpCodeGenerator otpCodeGenerator;
    private final OtpHasher otpHasher;
    private final OtpProperties props;

    private final Clock clock; // the current instant, date and time using a time-zone

    /*
     * POST http://localhost:8080/auth/signup/otp/request
     * "Content-Type: application/json"
     * '{"email":"add28482848@kyonggi.ac.kr"}'
     */
    @Transactional
    public void requestSignupOtp(String rawEmail) {
        String email = KyonggiEmailUtils.normalizeEmail(rawEmail); // 양끝 공백 제거 + 소문자 변환
        KyonggiEmailUtils.validateDomain(email); // 도메인 유효성 검사

        LocalDateTime now = LocalDateTime.now(clock);
        LocalDate today = now.toLocalDate();

        // OTP 중복성 검사 (해당 이메일의 레코드가 이미 있으면 반환)
        EmailOtp otp = emailOtpRepository.findByEmailAndPurpose(email, OtpPurpose.SIGNUP).orElse(null);

        if (otp != null) {
            // 1. 이미 검증된 상태이고 아직 만료 전이면 재요청 막기(가입 완료로 가게 유도)
            if (otp.isVerified() && !otp.isExpired(now)) {
                throw new ApiException(HttpStatus.CONFLICT, "OTP_ALREADY_VERIFIED",
                        "이미 인증이 완료되었습니다. 회원가입을 완료해주세요.");
            }

            // 2. 쿨다운 체크
            if (otp.getResendAvailableAt().isAfter(now)) {
                int retry = (int) java.time.Duration.between(now, otp.getResendAvailableAt()).getSeconds();
                throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "OTP_COOLDOWN",
                        "잠시 후 다시 시도해주세요.", Math.max(retry, 1));
            }

            // 3. 일일 제한 체크 (날짜 바뀌면 reissue() 안에서 카운트 리셋)
            int currentCount = otp.getSendCountDate().equals(today) ? otp.getSendCount() : 0;
            if (currentCount >= props.dailySendLimit()) {
                throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "OTP_DAILY_LIMIT",
                        "일일 OTP 발송 한도를 초과했습니다. 내일 다시 시도해주세요.");
            }
        }

        String code = otpCodeGenerator.generate6Digits(); // 6자리 코드 생성
        String codeHash = otpHasher.hash(code); // 6자리 코드 해시값
        LocalDateTime expiresAt = now.plusMinutes(props.ttlMinutes()); // +5분
        LocalDateTime resendAvailableAt = now.plusSeconds(props.resendCooldownSeconds()); // +60초

        if (otp == null) {
            // OTP 발행이 처음이라면 새로 발급
            otp = EmailOtp.create(email, codeHash, OtpPurpose.SIGNUP, expiresAt, now, today, resendAvailableAt);
        } else {
            // 위 조건들에 다 반하는 경우, OTP 인증코드 재발행
            otp.reissue(codeHash, expiresAt, now, today, resendAvailableAt);
        }

        emailOtpRepository.save(otp); // 이메일 otp 레코드 추가
        mailSender.sendOtp(email, code); // 경기대 회원 인증을 위해 이메일로 인증번호 발송
    }

    /*
     * POST http://localhost:8080/auth/signup/otp/verify \
     * "Content-Type: application/json" \
     * '{"email":"add28482848@kyonggi.ac.kr","code":"006809"}'
     */
    @Transactional
    public void verifySignupOtp(String rawEmail, String code) {
        String email = KyonggiEmailUtils.normalizeEmail(rawEmail);
        KyonggiEmailUtils.validateDomain(email);

        LocalDateTime now = LocalDateTime.now(clock);

        // OTP 요청 이력 조회 (무조건 레코드가 있어야 함)
        EmailOtp otp = emailOtpRepository.findByEmailAndPurpose(email, OtpPurpose.SIGNUP)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "OTP_NOT_FOUND",
                        "OTP 요청 이력이 없습니다. 먼저 인증번호를 요청해주세요."));

        // OTP가 만료되었는지 검사: "expires_at"
        if (otp.isExpired(now)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "OTP_EXPIRED", "인증번호가 만료되었습니다. 다시 요청해주세요.");
        }

        // 인증 시도 횟수 초과
        if (otp.getFailedAttempts() >= props.maxFailures()) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "OTP_TOO_MANY_FAILURES",
                    "인증 시도 횟수를 초과했습니다. 인증번호를 다시 요청해주세요.");
        }

        // 이미 검증된 경우 idempotent 처리
        if (otp.isVerified()) {
            return;
        }

        // 인증코드 비교
        if (!otpHasher.matches(code, otp.getCodeHash())) {
            otp.increaseFailure();
            emailOtpRepository.save(otp); // failed_attempt 증가시킨 뒤, OTP 레코드 업데이트
            throw new ApiException(HttpStatus.BAD_REQUEST, "OTP_INVALID", "인증번호가 올바르지 않습니다.");
        }

        otp.markVerified(now); // verified_at 업데이트 후
        emailOtpRepository.save(otp); // OTP 레코드 업데이트
    }

}
