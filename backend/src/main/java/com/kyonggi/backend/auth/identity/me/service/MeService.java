package com.kyonggi.backend.auth.identity.me.service;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.identity.me.dto.MeResponse;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.global.ApiException;
import com.kyonggi.backend.security.AuthPrincipal;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MeService {
    
    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public MeResponse me(AuthPrincipal principal) {

        if(principal == null || principal.userId() == null) {
            throw new ApiException(
                HttpStatus.UNAUTHORIZED, 
                "AUTH_REQUIRED", 
                "인증이 필요합니다.");
        }

        User user = userRepository.findById(principal.userId())
                .orElseThrow(() -> new ApiException(
                        HttpStatus.UNAUTHORIZED,
                        "USER_NOT_FOUND",
                        "사용자를 찾을 수 없습니다."
                ));

        return new MeResponse(
            user.getId(),
            user.getEmail(),
            user.getNickname(), 
            user.getRole().name(),
            user.getStatus().name());
    }

}
