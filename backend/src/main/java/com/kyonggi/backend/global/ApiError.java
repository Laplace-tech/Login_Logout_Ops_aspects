package com.kyonggi.backend.global;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * 공통 API 에러 응답 DTO
 * - record: 불변 객체, 단순 데이터 전달용
 * - 모든 에러 응답을 동일한 포맷으로 내려주기 위함
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(
        String code, // 에러 식별 코드
        String message, // 사용자에게 보여줄 에러 메세지
        Integer retryAfterSeconds, 
        Object details) {
    
    // 가장 기본적인 에러 생성
    public static ApiError of(String code, String message) {
        return new ApiError(code, message, null, null);
    }

    // 재시도 시간이 필요한 에러 생성
    public static ApiError of(String code, String message, Integer retryAfterSeconds) {
        return new ApiError(code, message, retryAfterSeconds, null);
    }

    public static ApiError of(String code, String message, Integer retryAfterSeconds, Object details) {
        return new ApiError(code, message, retryAfterSeconds, details);
    }
}
