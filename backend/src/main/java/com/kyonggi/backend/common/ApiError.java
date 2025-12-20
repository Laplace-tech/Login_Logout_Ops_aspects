package com.kyonggi.backend.common;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(
        String code,
        String message,
        Integer retryAfterSeconds,
        Object details) {
    public static ApiError of(String code, String message) {
        return new ApiError(code, message, null, null);
    }

    public static ApiError of(String code, String message, Integer retryAfterSeconds) {
        return new ApiError(code, message, retryAfterSeconds, null);
    }

    public static ApiError of(String code, String message, Integer retryAfterSeconds, Object details) {
        return new ApiError(code, message, retryAfterSeconds, details);
    }
}
