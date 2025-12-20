package com.kyonggi.backend.common;

import jakarta.validation.ConstraintViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @SuppressWarnings("null")
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> handle(ApiException e) {
        return ResponseEntity
                .status(e.getStatus())
                .body(ApiError.of(e.getCode(), e.getMessage(), e.getRetryAfterSeconds()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handle(MethodArgumentNotValidException e) {
        return ResponseEntity
                .status(BAD_REQUEST)
                .body(ApiError.of("VALIDATION_ERROR", "요청 값이 올바르지 않습니다."));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiError> handle(ConstraintViolationException e) {
        return ResponseEntity
                .status(BAD_REQUEST)
                .body(ApiError.of("VALIDATION_ERROR", "요청 값이 올바르지 않습니다."));
    }
}
