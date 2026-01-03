package com.kyonggi.backend.auth.refresh;

import java.sql.Timestamp;
import java.time.LocalDateTime;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import com.kyonggi.backend.auth.AbstractAuthIntegrationTest;
import com.kyonggi.backend.auth.token.support.TokenHashUtils;
import com.kyonggi.backend.global.ErrorCode;
import com.kyonggi.backend.support.AuthFlowSupport;
import com.kyonggi.backend.support.AuthHttpSupport;

import jakarta.servlet.http.Cookie;
 
@AutoConfigureMockMvc
@DisplayName("[Auth][Refresh] revoked/expired 보안 시나리오 통합 테스트")
class AuthRefreshSecurityIT extends AbstractAuthIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired TokenHashUtils tokenHashUtils;
    @Autowired JdbcTemplate jdbc;

    @Test
    @DisplayName("refresh: logout으로 revoke된 refresh로 refresh 시도 → 401 REFRESH_REVOKED")
    void refresh_after_logout_is_revoked() throws Exception {
        var login = AuthFlowSupport.loginOk(mvc, EMAIL, PASSWORD, false);
        String raw = login.refreshRaw();

        AuthHttpSupport.performLogout(mvc, new Cookie(AuthHttpSupport.REFRESH_COOKIE, raw))
                .andReturn();

        AuthHttpSupport.expectErrorWithCode(
                AuthHttpSupport.performRefresh(mvc, new Cookie(AuthHttpSupport.REFRESH_COOKIE, raw)),
                ErrorCode.REFRESH_REUSED
        );
    }

    @Test
    @DisplayName("refresh: expires_at 지난 refresh → 401 REFRESH_EXPIRED")
    void refresh_expired_token_is_blocked() throws Exception {
        var login = AuthFlowSupport.loginOk(mvc, EMAIL, PASSWORD, false);
        String raw = login.refreshRaw();

        String hash = tokenHashUtils.sha256Hex(raw);
        jdbc.update("update refresh_tokens set expires_at = ? where token_hash = ?",
                Timestamp.valueOf(LocalDateTime.now().minusDays(1)), hash);

        AuthHttpSupport.expectErrorWithCode(
                AuthHttpSupport.performRefresh(mvc, new Cookie(AuthHttpSupport.REFRESH_COOKIE, raw)),
                ErrorCode.REFRESH_EXPIRED
        );
    }
}
