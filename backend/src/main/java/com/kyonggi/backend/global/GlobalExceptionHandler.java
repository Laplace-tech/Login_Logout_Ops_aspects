package com.kyonggi.backend.global;

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
     * - 서비스/도메인 로직에서 의도적으로 던진 예외
     * - 예외 안에 들어있는 status, code, message를 그대로 사용
     */
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> handle(ApiException e) {
        return ResponseEntity
                .status(e.getStatus()) // ApiException이 가진 HTTP 상태 코드
                .body(ApiError.of(
                        e.getCode(),                 // 비즈니스 에러 코드
                        e.getMessage(),              // 사용자 메시지
                        e.getRetryAfterSeconds(),     // 재시도 시간(없으면 null)
                        e.getDetails()
                ));
    }

    /**
     * @RequestBody + @Valid 검증 실패 시 발생
     * - DTO 필드 단위 검증 오류
     * - 클라이언트에는 상세 정보 노출 안 하고
     *   서버 로그에만 필드/메시지 기록
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handle(MethodArgumentNotValidException e) {
        
        // 개발 편의: 어떤 필드가 왜 실패했는지 로그로만 남김
        e.getBindingResult().getFieldErrors()
                .forEach(fe -> log.error("Validation error: field={}, message={}", 
                            fe.getField(), 
                            fe.getDefaultMessage()));

        return ResponseEntity
                .status(BAD_REQUEST) // 응답은 항상 동일한 포맷으로 단순화
                .body(ApiError.of(
                        ErrorCode.VALIDATION_ERROR.name(),
                        ErrorCode.VALIDATION_ERROR.defaultMessage()));
    }

    /**
     * @RequestParam, @PathVariable, @Validated 검증 실패 시 발생
     * - 메서드 파라미터 단위 검증 오류
     * - 역시 클라이언트에는 상세 노출 없이 공통 메시지 반환
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiError> handle(ConstraintViolationException e) {
        return ResponseEntity
                .status(BAD_REQUEST)
                .body(ApiError.of(
                        ErrorCode.VALIDATION_ERROR.name(),
                        ErrorCode.VALIDATION_ERROR.defaultMessage())
                );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handle(Exception e) {
        log.error("Unhandled exception", e);
        return ResponseEntity
                .status(INTERNAL_SERVER_ERROR)
                .body(ApiError.of(
                        ErrorCode.INTERNAL_ERROR.name(), 
                        ErrorCode.INTERNAL_ERROR.defaultMessage()));
    }

}
