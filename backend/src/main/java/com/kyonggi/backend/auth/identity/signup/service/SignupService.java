package com.kyonggi.backend.auth.identity.signup.service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.regex.Pattern;

import org.springframework.dao.DataIntegrityViolationException;
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
        // 발송된 이메일 검증 및 정규화
        String email = normalizeKyonggiEmail(rawEmail);
        LocalDateTime now = LocalDateTime.now(clock);

        // 비밀번호 일치 검사 & 서비스 정책 검증
        validatePassword(rawPassword, rawPasswordConfirm);
        String nick = normalizeAndValidateNickname(nickname);

        // ✅ OTP도 락 조회하면 “동시에 complete 두 번” 같은 케이스에서 조금 더 단단해짐(선택)
        // 해당 이메일이 OTP 레코드에 있는지 검사 -> 없으면 OTP 인증 필요
        EmailOtp otp = emailOtpRepository.findByEmailAndPurposeForUpdate(email, OtpPurpose.SIGNUP)
                .orElseThrow(() -> new ApiException(ErrorCode.OTP_NOT_FOUND));


        // OTP 인증 미완료
        if (!otp.isVerified()) 
            throw new ApiException(ErrorCode.OTP_NOT_VERIFIED);

        // OTP 인증 만료, 재인증 필요(reissue)
        if (otp.getExpiresAt().isBefore(now)) 
            throw new ApiException(ErrorCode.OTP_EXPIRED);
        
        // 이메일 중복성 검사
        if (userRepository.existsByEmail(email)) 
            throw new ApiException(ErrorCode.EMAIL_ALREADY_EXISTS);
        
        // 닉네임 중복성 검사
        if (userRepository.existsByNickname(nick))
            throw new ApiException(ErrorCode.NICKNAME_ALREADY_EXISTS);
        

        String passwordHash = passwordEncoder.encode(rawPassword);

        try {
            userRepository.save(User.create(email, passwordHash, nick));
        } catch (DataIntegrityViolationException e) {
            // ✅ 레이스로 선체크를 통과해도 여기서 최종 차단됨.
            // 어떤 제약이 걸렸는지 구분하려면 "unique index 이름"을 보고 매핑하는 로직을 넣을 수 있음.
            // 지금은 보수적으로 email/nick 둘 다 다시 조회해서 에러코드 매핑.
            if (userRepository.existsByEmail(email)) {
                throw new ApiException(ErrorCode.EMAIL_ALREADY_EXISTS);
            }
            if (userRepository.existsByNickname(nick)) {
                throw new ApiException(ErrorCode.NICKNAME_ALREADY_EXISTS);
            }
            throw e; // 정말 다른 무결성 문제면 그대로 올림(또는 GENERIC_CONFLICT로 매핑)
        }

        // 재사용 방지: OTP 레코드 제거
        emailOtpRepository.delete(otp);
    }

    private String normalizeKyonggiEmail(String rawEmail) {
        KyonggiEmailUtils.validateKyonggiDomain(rawEmail);
        return KyonggiEmailUtils.normalize(rawEmail);
    }

    private void validatePassword(String rawPassword, String rawPasswordConfirm) {
        if (rawPassword == null || rawPasswordConfirm == null || !rawPassword.equals(rawPasswordConfirm)) {
            throw new ApiException(ErrorCode.PASSWORD_MISMATCH);
        }
        if (!PASSWORD_PATTERN.matcher(rawPassword).matches()) {
            throw new ApiException(ErrorCode.WEAK_PASSWORD);
        }
    }

    private String normalizeAndValidateNickname(String nickname) {
        String nick = nickname == null ? "" : nickname.trim();
        if (!NICKNAME_PATTERN.matcher(nick).matches()) {
            throw new ApiException(ErrorCode.INVALID_NICKNAME);
        }
        return nick;
    }
}
