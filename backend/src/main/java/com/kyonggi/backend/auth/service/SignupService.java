package com.kyonggi.backend.auth.service;

import com.kyonggi.backend.auth.domain.EmailOtp;
import com.kyonggi.backend.auth.domain.OtpPurpose;
import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.repo.EmailOtpRepository;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.auth.support.KyonggiEmailUtils;
import com.kyonggi.backend.auth.support.SignupPatterns;
import com.kyonggi.backend.common.ApiException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class SignupService {

    private final EmailOtpRepository emailOtpRepository;
    private final UserRepository userRepository;

    private final Clock clock;
    private final PasswordEncoder passwordEncoder;

    // ✅ 정규식은 "문자열 상수"로 관리하고, Pattern은 static final로 한 번만 컴파일
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(SignupPatterns.PASSWORD_REGEX);
    private static final Pattern NICKNAME_PATTERN = Pattern.compile(SignupPatterns.NICKNAME_REGEX);

    @Transactional
    public void completeSignup(String rawEmail, String rawPassword, String rawPasswordConfirm, String nickname) {
        String email = KyonggiEmailUtils.normalizeEmail(rawEmail);
        KyonggiEmailUtils.validateDomain(email);

        LocalDateTime now = LocalDateTime.now(clock);

        // password confirm
        if (rawPassword == null || rawPasswordConfirm == null || !rawPassword.equals(rawPasswordConfirm)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "PASSWORD_MISMATCH", "비밀번호가 일치하지 않습니다.");
        }

        // password policy
        if (!PASSWORD_PATTERN.matcher(rawPassword).matches()) {
            throw new ApiException(
                    HttpStatus.BAD_REQUEST,
                    "WEAK_PASSWORD",
                    "비밀번호는 9~15자, 영문+숫자+특수문자를 포함하고 공백이 없어야 합니다.");
        }

        String nick = nickname == null ? "" : nickname.trim();

        // nickname policy
        if (!NICKNAME_PATTERN.matcher(nick).matches()) {
            throw new ApiException(
                    HttpStatus.BAD_REQUEST,
                    "INVALID_NICKNAME",
                    "닉네임은 2~20자, 한글/영문/숫자/_(언더스코어)만 허용하며 공백은 불가합니다.");
        }

        EmailOtp otp = emailOtpRepository.findByEmailAndPurpose(email, OtpPurpose.SIGNUP)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "OTP_NOT_FOUND", "OTP 인증이 필요합니다."));

        if (!otp.isVerified()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "OTP_NOT_VERIFIED", "OTP 인증을 먼저 완료해주세요.");
        }

        if (otp.getExpiresAt().isBefore(now)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "OTP_EXPIRED", "인증이 만료되었습니다. 다시 인증해주세요.");
        }

        if (userRepository.existsByEmail(email)) {
            throw new ApiException(HttpStatus.CONFLICT, "EMAIL_ALREADY_EXISTS", "이미 가입된 이메일입니다.");
        }

        if (userRepository.existsByNickname(nick)) {
            throw new ApiException(HttpStatus.CONFLICT, "NICKNAME_ALREADY_EXISTS", "이미 사용 중인 닉네임입니다.");
        }

        String passwordHash = passwordEncoder.encode(rawPassword);
        userRepository.save(User.create(email, passwordHash, nick));

        // 재사용 방지: OTP 레코드 제거
        emailOtpRepository.delete(otp);
    }
}
