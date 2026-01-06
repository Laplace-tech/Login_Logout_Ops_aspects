package com.kyonggi.backend.auth.identity.me.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.domain.UserStatus;
import com.kyonggi.backend.auth.identity.me.dto.MeResponse;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.global.ApiException;
import com.kyonggi.backend.global.ErrorCode;
import com.kyonggi.backend.security.AuthPrincipal;

import lombok.RequiredArgsConstructor;

/** 
 * [내 정보 조회]
 * 
 * - 인증 Principal을 입력으로 받아 DB에서 User를 조회한다.
 * - 사용자 상태 정책(예: 비활성/정지) 등을 검사한다.
 * - 응답 DTO(MeResponse)로 변환하여 반환한다.
 */
@Service
@RequiredArgsConstructor
public class MeService {

    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public MeResponse me(AuthPrincipal principal) {

        // 계층별 방어: 인증이 없으면 principal이 null로 들어올 수 있음
        if (principal == null || principal.userId() == null) {
            throw new ApiException(ErrorCode.AUTH_REQUIRED);
        }

        User user = userRepository.findById(principal.userId())
                .orElseThrow(() -> new ApiException(ErrorCode.USER_NOT_FOUND)); // @DisplayName("me: 토큰은 유효하지만 DB에 유저 없음 → USER_NOT_FOUND")

        // 계정 상태가 ACTIVE가 아니면 차단
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ApiException(ErrorCode.ACCOUNT_DISABLED); // @DisplayName("me: 토큰은 유효하지만 비활성 계정 → ACCOUNT_DISABLED")
        }

        return MeResponse.from(user);
    }
}
