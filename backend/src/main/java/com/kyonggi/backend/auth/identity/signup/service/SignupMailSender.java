package com.kyonggi.backend.auth.identity.signup.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

import com.kyonggi.backend.auth.config.OtpProperties;

import lombok.RequiredArgsConstructor;

/**
 * 회원 가입 OTP 메일 발송 컴포넌트
 * 
 * @Component
 * - 비즈니스 서비스가 아닌 "외부 I/O 어댑터"
 * - 메일 발송이라는 기술적 관심사만 담당
 * 
 * @Service가 직접 JavaMailSender를 쓰지 않고 
 *  이 클래스를 거친다 -> 관심사 분리 (SRP) 
 */
@Component
@RequiredArgsConstructor
public class SignupMailSender {

    private final JavaMailSender mailSender;
    private final OtpProperties props;

    public void sendOtp(String toEmail, String code) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(toEmail);
        msg.setSubject("[경기대 커뮤니티] 회원가입 인증번호");
        msg.setText("인증번호: " + code + "\n\n" + props.ttlMinutes() + "분 이내에 입력해주세요.");
        mailSender.send(msg);
    }
}
