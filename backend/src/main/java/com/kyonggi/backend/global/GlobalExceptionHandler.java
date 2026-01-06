package com.kyonggi.backend.global;

import org.springframework.http.HttpHeaders;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;

/**
 * 전역 예외 처리기
 * - 컨트롤러/서비스에서 발생한 예외를 가로채
 * - HTTP 상태 코드 + ApiError 포맷으로 통일된 응답을 반환
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    /**
     * ApiException 전용 핸들러
     * - 비즈니스 로직이 의도적으로 던진 예외를 처리한다.
     * - ApiException의 필드들(message/status/code/retryAfterSeconds/details)을 표준 응답(ApiError)로 변환
     * + retryAfterSeconds가 있으면 Retry-After 헤더도 같이 내려줌(특히 429)
     */
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> handleApiException(ApiException e) {
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(e.getStatus());

        if (e.getRetryAfterSeconds() != null) {
            builder.header(HttpHeaders.RETRY_AFTER, String.valueOf(e.getRetryAfterSeconds()));
        }

        return builder.body(ApiError.from(e));
    }

    /**
     * @RequestBody + @Valid 검증 실패
     * - DTO 필드 단위 오류
     * - 응답은 VALIDATION_ERROR로 단순화(상세는 로그로만)
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleMethodArgumentNotValid(MethodArgumentNotValidException e) {

        // 운영 기준: validation은 보통 warn이 적당함 (에러급 장애는 아님)
        e.getBindingResult().getFieldErrors()
                .forEach(fe -> log.error("Validation error: field={}, message={}",
                        fe.getField(),
                        fe.getDefaultMessage()));

        return ResponseEntity
                .status(BAD_REQUEST)
                .body(ApiError.of(ErrorCode.VALIDATION_ERROR));
    }

    /**
     * @RequestParam / @PathVariable / @Validated 검증 실패
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiError> handleConstraintViolation(ConstraintViolationException e) {
        e.getConstraintViolations().forEach(v ->
                log.error("Constraint violation: path={}, message={}",
                        v.getPropertyPath(),
                        v.getMessage())
        );

        return ResponseEntity
                .status(BAD_REQUEST)
                .body(ApiError.of(ErrorCode.VALIDATION_ERROR));
    }

    /**
     * 처리되지 않은 예외(버그/장애 케이스)
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUnhandled(Exception e) {
        log.error("Unhandled exception", e);
        return ResponseEntity
                .status(INTERNAL_SERVER_ERROR)
                .body(ApiError.of(ErrorCode.INTERNAL_ERROR));
    }

}
