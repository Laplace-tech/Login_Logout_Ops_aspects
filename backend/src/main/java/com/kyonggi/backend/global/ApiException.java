package com.kyonggi.backend.global;

import org.springframework.http.HttpStatus;

import lombok.Getter;

/**
 * 비즈니스 로직에서 사용하는 실무형 커스텀 예외 (중앙화된 ErrorCode 기반)
 * 
 * - 서비스 계층에서 정책 위반을 발견하면, 아래와 같은 방식으로 예외를 생성해 던짐.
 *  => throw new ApiException(ErrorCode.REFRESH_EXPIRED);
 * 
 *  이때, ErrorCode는 (HttpStatus status, String defaultMessage) 필드로 구성되어 있으므로
 *   ApiException 예외 클래스에 다음과 같이 값을 채워넣음
 * 
 *      class ApiException {
 *          super(message) : message = errorCode.defaultMessage() // "리프레쉬 토큰이 만료되었습니다."
 *          this.status = errorCode.status()           // HttpStatus.UNAUTHORIZED
 *          this.code = errorCode.name()               // REFRESH_EXPIRED
 *          this.retryAfterSeconds = <option1>
 *          this.details = <option2>
 *      }
 * 
 *   위와 같이 필드에 값을 채우고 예외를 throw로 날리면 GlobalExceptionHandler가 해당 예외를 잡는다.
 *    전역 예외 처리기(GlobalExceptionHandler)는 클라이언트에게 JSON으로 전송할 ApiError 객체를 만들어
 *    ResponseEntity<ApiError>에 담아 반환한다.
 *  
 *      public ResponseEntity<ApiError> handleApiException(ApiException e) {
 *          ResponseEntity.BodyBuilder builder = ResponseEntity.status(e.getStatus()); // HttpStatus.UNAUTHORIZED
 *          return builder.body(new ApiError(e.getCode(),    // REFRESH_EXPIRED
 *                                           e.getMessage(), // "리프레쉬 토큰이 만료되었습니다."
 *                                           e.getRetryAfterSeconds(), 
 *                                           e.getDetails()));
 *      }
 */

@Getter
public class ApiException extends RuntimeException {

    private final HttpStatus status; // HTTP 응답 상태코드
    private final String code; // 에러 식별 코드
    private final Integer retryAfterSeconds; // 재시도 가능 시간
    private final Object details;

    /**
     * 실무형(중앙화된 ErrorCode 기반)
     * - 서비스 계층에서 예외 발생 시, 아래와 같은 방식으로 예외를 생성해 던짐.
     * => throw new ApiException(ErrorCode.REFRESH_EXPIRED);
     */
    public ApiException(ErrorCode errorCode) {
        this(errorCode, errorCode.defaultMessage(), null, null);
    }

    public ApiException(ErrorCode errorCode, String messageOverride) {
        this(errorCode, messageOverride, null, null);
    }

    public ApiException(ErrorCode errorCode, Integer retryAfterSeconds) {
        this(errorCode, errorCode.defaultMessage(), retryAfterSeconds, null);
    }

    public ApiException(ErrorCode errorCode, Integer retryAfterSeconds, Object details) {
        this(errorCode, errorCode.defaultMessage(), retryAfterSeconds, details);
    }

    public ApiException(ErrorCode errorCode, String messageOverride, Integer retryAfterSeconds, Object details) {
        super(messageOverride);
        this.status = errorCode.status();
        this.code = errorCode.name();
        this.retryAfterSeconds = retryAfterSeconds;
        this.details = details;
    }
}