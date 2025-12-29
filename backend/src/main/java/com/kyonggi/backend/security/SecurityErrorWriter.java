package com.kyonggi.backend.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyonggi.backend.global.ApiError;
import com.kyonggi.backend.global.ErrorCode;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class SecurityErrorWriter {
    
    private final ObjectMapper objectMapper;

    public void write(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        
        // 이미 다른 필터가 응답을 만들어버린 경우라면 건드리지 않음
        if (response.isCommitted()) 
            return;

        response.setStatus(errorCode.status().value()); // ex: 401 Unauthorized
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE); // ex: "application/json"

        objectMapper.writeValue(response.getWriter(), 
            ApiError.of(
                errorCode.name(), // "AUTH_REQUIRED"
                errorCode.defaultMessage() // "인증이 필요합니다."
            ));
    }

    public void write(HttpServletResponse response, ErrorCode errorCode, String messageOverride) throws IOException {
        if(response.isCommitted()) 
            return;

        response.setStatus(errorCode.status().value());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        objectMapper.writeValue(response.getWriter(), 
            ApiError.of(
                errorCode.name(), 
                messageOverride
            ));
    }

}
