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

    public ApiException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
        this.retryAfterSeconds = null;
    }

    public ApiException(HttpStatus status, String code, String message, Integer retryAfterSeconds) {
        super(message);
        this.status = status;
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
    }
}