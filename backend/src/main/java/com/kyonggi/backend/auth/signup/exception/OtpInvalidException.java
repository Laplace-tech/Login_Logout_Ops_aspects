package com.kyonggi.backend.auth.signup.exception;

import org.springframework.http.HttpStatus;

import com.kyonggi.backend.common.ApiException;

/**
 * OTP 인증번호 불일치 전용 예외(표식 예외)
 * - 이 예외만 noRollbackFor로 처리해서 failedAttempts 증가가 DB에 커밋되게 한다.
 */
public class OtpInvalidException extends ApiException {
    public OtpInvalidException() {
        super(
            HttpStatus.BAD_REQUEST, 
            "OTP_INVALID", 
            "인증번호가 올바르지 않습니다."
        );
    }
}