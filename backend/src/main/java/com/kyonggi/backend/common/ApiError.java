package com.kyonggi.backend.common;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(
        String code,
        String message,
        Integer retryAfterSeconds
) {
    public static ApiError of(String code, String message) {
        return new ApiError(code, message, null);
    }

    public static ApiError of(String code, String message, Integer retryAfterSeconds) {
        return new ApiError(code, message, retryAfterSeconds);
    }
}