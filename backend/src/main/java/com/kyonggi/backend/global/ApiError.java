package com.kyonggi.backend.global;

import com.fasterxml.jackson.annotation.JsonInclude;


/**
 * [공통 API 에러 응답 DTO: 모든 에러 응답을 동일한 포맷으로 내려주기 위함]
 * 
 * - code: 프로그램이 분기할 안정적인 에러 식별자 (ex: OTP_COOLDOWN)
 * - message: 사용자에게 보여줄 문장(로케일/정책에 따라 변경 가능)
 * - retryAfterSeconds: 재시도 가능 시간(주로 429 에서 사용)
 * - details: 디버깅/추가정보(필요할 때만, 없으면 null)
 * 
 * 1) record <className>(...)
 *  - 불변 데이터 묶음, 단순 데이터 전달용 DTO
 * 
 * 2) @JsonInclude(NON_NULL)
 *  - JSON으로 내려줄 때 null인 필드는 전부 제외시키기
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(
        String code,    // 에러 식별 코드
        String message, // 사용자에게 보여줄 에러 메세지
        Integer retryAfterSeconds, 
        Object details
) {
    
    public static ApiError of(ErrorCode errorCode) {
        return new ApiError(errorCode.name(), errorCode.defaultMessage(), null, null);
    }

    public static ApiError of(ErrorCode errorCode, String messageOverride) {
        return new ApiError(errorCode.name(), messageOverride, null, null);
    }

    public static ApiError of(ErrorCode errorCode, Integer retryAfterSeconds) {
        return new ApiError(errorCode.name(), errorCode.defaultMessage(), retryAfterSeconds, null);
    }

    public static ApiError of(ErrorCode errorCode, Integer retryAfterSeconds, Object details) {
        return new ApiError(errorCode.name(), errorCode.defaultMessage(), retryAfterSeconds, details);
    }

    public static ApiError from(ApiException e) {
        return new ApiError(e.getCode(), e.getMessage(), e.getRetryAfterSeconds(), e.getDetails());
    }

}
