package com.kyonggi.backend.auth.identity.signup.event;

import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import com.kyonggi.backend.auth.identity.signup.service.SignupMailSender;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class SignupOtpMailEventListener {

    private final SignupMailSender mailSender;

    // DB 트랜잭션이 성공적으로 커밋이 된 뒤에만 실행된다. (커밋 실패/롤백이면 메일이 안나감)
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void on(SignupOtpIssuedEvent event) {
        try {
            mailSender.sendOtp(event.email(), event.code());
        } catch (Exception e) {
            log.error("Failed to send signup OTP mail. email={}", event.email(), e);
        }
    }

}
