package com.kyonggi.backend.global;

import org.springframework.http.HttpStatus;

import lombok.Getter;

/**
 * 비즈니스 로직에서 사용하는 커스텀 예외
 * - 컨트롤러/서비스 어디서든 에러를 던질 때
 *   HTTP 상태 코드 + 에러 코드 + 메시지를 함께 전달하기 위함
 * - GlobalExceptionHandler에서 이 예외 하나로 공통 처리
 */
@Getter
public class ApiException extends RuntimeException {
    
    private final HttpStatus status; // HTTP 응답 상태코드
    private final String code; // 에러 식별 코드
    private final Integer retryAfterSeconds; // 재시도 가능 시간
    private final Object details;

    // ✅ 실무형(중앙화된 ErrorCode 기반)
    public ApiException(ErrorCode errorCode) {
        super(errorCode.defaultMessage());
        this.status = errorCode.status();
        this.code = errorCode.name();
        this.retryAfterSeconds = null;
        this.details = null;
    }

    public ApiException(ErrorCode errorCode, String messageOverride) {
        super(messageOverride);
        this.status = errorCode.status();
        this.code = errorCode.name();
        this.retryAfterSeconds = null;
        this.details = null;
    }

    public ApiException(ErrorCode errorCode, Integer retryAfterSeconds) {
        super(errorCode.defaultMessage());
        this.status = errorCode.status();
        this.code = errorCode.name();
        this.retryAfterSeconds = retryAfterSeconds;
        this.details = null;
    }

    public ApiException(ErrorCode errorCode, Integer retryAfterSeconds, Object details) {
        super(errorCode.defaultMessage());
        this.status = errorCode.status();
        this.code = errorCode.name();
        this.retryAfterSeconds = retryAfterSeconds;
        this.details = details;
    }

    public ApiException(ErrorCode errorCode, String messageOverride, Integer retryAfterSeconds, Object details) {
        super(messageOverride);
        this.status = errorCode.status();
        this.code = errorCode.name();
        this.retryAfterSeconds = retryAfterSeconds;
        this.details = details;
    }
}