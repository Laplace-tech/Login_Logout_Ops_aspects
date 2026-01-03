package com.kyonggi.backend.auth.me;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.kyonggi.backend.auth.AbstractAuthIntegrationTest;
import com.kyonggi.backend.auth.domain.UserRole;
import com.kyonggi.backend.auth.domain.UserStatus;
import com.kyonggi.backend.global.ErrorCode;
import com.kyonggi.backend.support.AuthFlowSupport;
import com.kyonggi.backend.support.AuthHttpSupport;
import com.kyonggi.backend.support.AuthHttpSupport.LoginResult;

@DisplayName("[Auth][Me] 내 정보 조회(/auth/me) 통합 테스트")
class AuthMeIT extends AbstractAuthIntegrationTest {

    @Autowired MockMvc mvc;
 
    @Test
    @DisplayName("me: 유효한 access 토큰 → 200 + 사용자 정보 반환")
    void me_returns_user_info_when_access_token_valid() throws Exception {
        // 1) 로그인해서 accessToken 획득
        LoginResult login = AuthFlowSupport.loginOk(mvc, EMAIL, PASSWORD, false);

        // 2) accessToken을 Bearer로 넣으면 성공 200 + 내 정보 JSON 반환
        AuthHttpSupport.performMe(mvc, AuthHttpSupport.bearer(login.accessToken()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.userId").isNumber())
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.nickname").value(NICKNAME))
                .andExpect(jsonPath("$.role").value(UserRole.USER.name()))
                .andExpect(jsonPath("$.status").value(UserStatus.ACTIVE.name()));
    }

    @Test
    @DisplayName("me: 인증 없음 → 401 AUTH_REQUIRED")
    void me_requires_auth() throws Exception {
        AuthHttpSupport.expectErrorWithCode(
                AuthHttpSupport.performMe(mvc, null),
                ErrorCode.AUTH_REQUIRED
        );
    }

    @Test
    @DisplayName("me: Bearer가 아닌 Authorization → 401 AUTH_REQUIRED")
    void me_rejects_non_bearer_header_as_unauthenticated() throws Exception {
        AuthHttpSupport.expectErrorWithCode(
                AuthHttpSupport.performMe(mvc, "Basic abcdefg"),
                ErrorCode.AUTH_REQUIRED
        );
    }

    @Test
    @DisplayName("me: 형식/서명 불량 JWT → 401 ACCESS_INVALID")
    void me_rejects_invalid_jwt() throws Exception {
        AuthHttpSupport.expectErrorWithCode(
                AuthHttpSupport.performMe(mvc, "Bearer not-a-jwt"),
                ErrorCode.ACCESS_INVALID
        );
    }

    @Test
    @DisplayName("me: refresh 토큰을 access처럼 사용 → 401 ACCESS_INVALID")
    void me_rejects_refresh_token_string_used_as_access_token() throws Exception {
        var login = AuthFlowSupport.loginOk(mvc, EMAIL, PASSWORD, false);

        AuthHttpSupport.expectErrorWithCode(
                AuthHttpSupport.performMe(mvc, AuthHttpSupport.bearer(login.refreshRaw())),
                ErrorCode.ACCESS_INVALID
        );
    }
}
