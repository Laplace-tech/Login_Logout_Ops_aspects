package com.kyonggi.backend.auth.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class SignupMailSender {
    private final JavaMailSender mailSender;

    public void sendOtp(String toEmail, String code) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(toEmail);
        msg.setSubject("[경기대 커뮤니티] 회원가입 인증번호");
        msg.setText("인증번호: " + code + "\n\n5분 이내에 입력해주세요.");
        mailSender.send(msg);
    }
}
