package com.kyonggi.backend.auth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import com.kyonggi.backend.auth.AuthTestSupport.LoginResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * - /auth/me 엔드포인트가 JWT AccessToken 기반으로 인증을 요구한다.
 * - 토큰이 유효하면 현재 사용자 정보를 반환하는지 검증한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("[Auth][Me] 내 정보 조회(/auth/me) 통합 테스트")
class AuthMeIntegrationTest extends AbstractAuthIntegrationTest {
  
    @Autowired MockMvc mvc;

    @Test
    @DisplayName("me: 유효한 access 토큰 → 200 + 사용자 정보 반환")
    void me_returns_user_info_when_access_token_valid() throws Exception {
        // 로그인해서 accessToken을 얻는다
        LoginResult login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, false);

        // accessToken을 Bearer로 넣으면 성공 200 + 내 정보 JSON 반환
        mvc.perform(get("/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + login.accessToken()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.userId").isNumber())
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.nickname").value(NICKNAME))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    @DisplayName("me: 인증 없음 → 401 AUTH_REQUIRED")
    void me_requires_auth() throws Exception {
        // Authorization 헤더가 없으면 인증이 안되므로 401 + AUTH_REQUIRED
        mvc.perform(get("/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTH_REQUIRED"));
    }

    @Test
    @DisplayName("me: Bearer가 아닌 Authorization → 401 AUTH_REQUIRED")
    void me_rejects_non_bearer_header_as_unauthenticated() throws Exception {
        // Bearer가 아닌 Authorization은 인증으로 인정하지 않는다
        // 예: "Basic ..." 같은 건 AUTH_REQUIRED로 처리
        mvc.perform(get("/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Basic abcdefg"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTH_REQUIRED"));
    }

    @Test
    @DisplayName("me: 형식/서명 불량 JWT → 401 ACCESS_INVALID")
    void me_rejects_invalid_jwt() throws Exception {
        // Bearer 형식은 맞지만 JWT 형태가 아닌 쓰레기 토큰 -> ACCESS_INVALID
        mvc.perform(get("/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("ACCESS_INVALID"));
    }

    @Test
    @DisplayName("me: refresh 토큰을 access처럼 사용 → 401 ACCESS_INVALID")
    void me_rejects_refresh_token_string_used_as_access_token() throws Exception {
        // 로그인하면 refreshRaw를 얻는다 (하지만 refresh는 access가 아님)
        LoginResult login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, false);

        // refresh 토큰 문자열을 access처럼 Bearer로 넣으면 당연히 검증 실패 -> ACCESS_INVALID
        mvc.perform(get("/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + login.refreshRaw()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("ACCESS_INVALID"));
    }


}
