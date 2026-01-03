package com.kyonggi.backend.auth.login;

import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

import com.kyonggi.backend.auth.AbstractAuthIntegrationTest;
import com.kyonggi.backend.auth.domain.UserStatus;
import com.kyonggi.backend.global.ErrorCode;
import com.kyonggi.backend.support.AuthHttpSupport;

@AutoConfigureMockMvc
@DisplayName("[Auth][Login] 로그인 실패 시나리오 통합 테스트")
class AuthLoginIT extends AbstractAuthIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;

    @Test 
    @DisplayName("login: 비밀번호 틀림 → 401 INVALID_CREDENTIALS + Set-Cookie 없음")
    void login_wrong_password() throws Exception {
        var actions = AuthHttpSupport.performLogin(mvc, EMAIL, "wrong-password", false);

        AuthHttpSupport.expectErrorWithCode(actions, ErrorCode.INVALID_CREDENTIALS);
        actions.andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
    }

    @Test
    @DisplayName("login: 존재하지 않는 이메일 → 401 INVALID_CREDENTIALS")
    void login_unknown_email() throws Exception {
        AuthHttpSupport.expectErrorWithCode(
                AuthHttpSupport.performLogin(mvc, "noone@kyonggi.ac.kr", "whatever123!", false),
                ErrorCode.INVALID_CREDENTIALS
        );
    }

    @Test
    @DisplayName("login: 비활성 계정 → 403 ACCOUNT_DISABLED")
    void login_disabled_account() throws Exception {
        // ACTIVE가 아닌 아무 상태로 강제 세팅 (enum 값이 뭐든 “ACTIVE가 아니면” 막히게 설계되어 있을 확률이 높음)
        String nonActive = Arrays.stream(UserStatus.values())
                .map(Enum::name)
                .filter(v -> !v.equals("ACTIVE"))
                .findFirst()
                .orElse("DISABLED");

        jdbc.update("update users set status = ? where email = ?", nonActive, EMAIL);

        AuthHttpSupport.expectErrorWithCode(
                AuthHttpSupport.performLogin(mvc, EMAIL, PASSWORD, false),
                ErrorCode.ACCOUNT_DISABLED
        );
    }
}
