package com.kyonggi.backend.auth.logout;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.kyonggi.backend.auth.AbstractAuthIntegrationTest;
import com.kyonggi.backend.auth.token.domain.RefreshRevokeReason;
import com.kyonggi.backend.auth.token.domain.RefreshToken;
import com.kyonggi.backend.auth.token.support.TokenHashUtils;
import com.kyonggi.backend.support.AuthFlowSupport;
import com.kyonggi.backend.support.AuthHttpSupport;
import com.kyonggi.backend.support.AuthHttpSupport.LoginResult;

import jakarta.servlet.http.Cookie;

 
@DisplayName("[Auth][Logout] 로그아웃(/auth/logout) 통합 테스트")
class AuthLogoutIT extends AbstractAuthIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired TokenHashUtils tokenHashUtils;

    @Test
    @DisplayName("logout: refresh 쿠키 있음 → DB 토큰 revoke(LOGOUT) + 쿠키 삭제(Max-Age=0)")
    void logout_with_cookie_revokes_token_and_clears_cookie() throws Exception {
        // 로그인해서 refreshRaw(쿠키 값)를 얻는다
        LoginResult login = AuthFlowSupport.loginOk(mvc, EMAIL, PASSWORD, false);
        String refreshRaw = login.refreshRaw();
        
        // 로그아웃 전에 DB에 토큰이 저장되어 있어야 한다
        String hash = tokenHashUtils.sha256Hex(refreshRaw);
        assertThat(refreshTokenRepository.findByTokenHash(hash)).isPresent();

        // refresh 쿠키를 포함해서 /auth/logout 호출
        MvcResult res = AuthHttpSupport.performLogout(mvc, new Cookie(AuthHttpSupport.REFRESH_COOKIE, refreshRaw))
                .andExpect(status().isNoContent())                        // 로그아웃 성공은 보통 204
                .andExpect(header().exists(HttpHeaders.SET_COOKIE))       // 쿠키 삭제를 위해 Set-Cookie가 내려와야 함
                .andReturn();

        // 5) 응답 Set-Cookie에서 refresh 쿠키 삭제 정책 확인
        String setCookieLine = AuthHttpSupport.findSetCookieLine(
                res.getResponse().getHeaders(HttpHeaders.SET_COOKIE),
                AuthHttpSupport.REFRESH_COOKIE
        );

        // 삭제 쿠키는 보통 Max-Age=0 + Expires=... 같이 내려옴
        AuthHttpSupport.assertRefreshCookieCleared(setCookieLine);

        // DB 토큰 revoke 처리 확인 + reason=LOGOUT
        Optional<RefreshToken> row = refreshTokenRepository.findByTokenHash(hash);
        assertThat(row).isPresent();
        assertThat(row.get().isRevoked()).isTrue();
        assertThat(row.get().getRevokeReason().toString())
                .isEqualTo(RefreshRevokeReason.LOGOUT.name());
    }

    @Test
    @DisplayName("logout: 쿠키 없음 → 204 (idempotent)")
    void logout_without_cookie_is_idempotent() throws Exception {
        // 쿠키가 없어도 그냥 204로 성공 처리 (이미 로그아웃 상태로 간주)
        AuthHttpSupport.performLogout(mvc, null)
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("logout: 미발급 쿠키 → 204 (idempotent) + 쿠키 삭제(Max-Age=0)")
    void logout_with_unknown_cookie_is_idempotent_and_clears_cookie() throws Exception {
        // 서버가 발급한 적 없는 쿠키여도 204 성공 + 쿠키 삭제로 내려 클라이언트 상태를 정리
        MvcResult res = AuthHttpSupport.performLogout(mvc, new Cookie(AuthHttpSupport.REFRESH_COOKIE, "not-issued"))
                .andExpect(status().isNoContent())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE))
                .andReturn();

        String setCookieLine = AuthHttpSupport.findSetCookieLine(
                res.getResponse().getHeaders(HttpHeaders.SET_COOKIE),
                AuthHttpSupport.REFRESH_COOKIE
        );

        assertThat(setCookieLine).contains("Max-Age=0");
    }
}
