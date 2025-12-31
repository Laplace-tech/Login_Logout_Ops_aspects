package com.kyonggi.backend.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.kyonggi.backend.auth.AuthTestSupport.LoginResult;
import com.kyonggi.backend.auth.token.domain.RefreshToken;
import com.kyonggi.backend.auth.token.support.TokenHashUtils;

import jakarta.servlet.http.Cookie;

/**
 * - /auth/logout 이 refresh 쿠키 기반으로 DB 토큰을 REVOKE 처리하고,
 *    쿠키를 삭제(Max-Age=0)로 내려주는지 검증한다.
 * - 쿠키가 없거나, 서버가 발급한 적 없는 쿠키여도 
 *    "idempotent"(항상 성공)하게 동작하는지 검증한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("[Auth][Logout] 로그아웃(/auth/logout) 통합 테스트")
class AuthLogoutIntegrationTest extends AbstractAuthIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired TokenHashUtils tokenHashUtils;

    @Test
    @DisplayName("logout: refresh 쿠키 있음 → DB 토큰 revoke(LOGOUT) + 쿠키 삭제(Max-Age=0)")
    void logout_with_cookie_revokes_token_and_clears_cookie() throws Exception {
        // 로그인해서 refresh 쿠키 raw 값을 얻고, DB 저장 hash를 구한다
        LoginResult login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, false);
        String refreshRaw = login.refreshRaw();
        String hash = tokenHashUtils.sha256Hex(refreshRaw);

        // DB에 refresh가 저장되어 있어야 함
        assertThat(refreshTokenRepository.findByTokenHash(hash)).isPresent();

        /**
         * refresh 쿠키를 포함해서 /auth/logout 호출 
         * - 로그아웃 성공은 204 No Content
         * - 서버는 쿠키 삭제(Set-Cookie)로 내려줘야 함
         */
        MvcResult res = mvc.perform(post("/auth/logout")
                        .cookie(new Cookie(AuthTestSupport.REFRESH_COOKIE, refreshRaw)))
                .andExpect(status().isNoContent())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE))
                .andReturn();

        // 응답 Set-Cookie 라인에서 refresh 쿠키 삭제 정책 확인
        String setCookie = AuthTestSupport.findSetCookieLine(
                res.getResponse().getHeaders(HttpHeaders.SET_COOKIE),
                AuthTestSupport.REFRESH_COOKIE
        );

        assertThat(setCookie).contains("Path=/auth");

        // 삭제 쿠키는 Max-Age=0, Expires 과 같이 내려오는 형태가 일반적
        assertThat(setCookie).contains("Max-Age=0");
        assertThat(setCookie).contains("Expires=");
        assertThat(setCookie).contains("HttpOnly");
        assertThat(setCookie).contains("SameSite=Lax");

        // DB 토큰 revoke 처리 확인 + reason=LOGOUT
        Optional<RefreshToken> row = refreshTokenRepository.findByTokenHash(hash);
        assertThat(row).isPresent();
        assertThat(row.get().isRevoked()).isTrue();
        assertThat(row.get().getRevokeReason()).isEqualTo("LOGOUT");
    }

    @Test
    @DisplayName("logout: 쿠키 없음 → 204 (idempotent)")
    void logout_without_cookie_is_idempotent() throws Exception {
        // 쿠키가 없어도 로그아웃은 "그냥 성공"하는 게 UX/보안상 흔한 정책
        // (이미 로그아웃 상태로 간주)
        mvc.perform(post("/auth/logout"))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("logout: 미발급 쿠키 → 204 (idempotent) + 쿠키 삭제(Max-Age=0)")
    void logout_with_unknown_cookie_is_idempotent_and_clears_cookie() throws Exception {
        // 서버가 발급한 적 없는 쿠키를 주더라도
        // 204로 성공 처리 + 쿠키는 삭제로 내려서 클라이언트 상태를 정리한다
        MvcResult res = mvc.perform(post("/auth/logout")
                        .cookie(new Cookie(AuthTestSupport.REFRESH_COOKIE, "not-issued")))
                .andExpect(status().isNoContent())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE))
                .andReturn();

        String setCookie = AuthTestSupport.findSetCookieLine(
                res.getResponse().getHeaders(HttpHeaders.SET_COOKIE),
                AuthTestSupport.REFRESH_COOKIE
        );

        assertThat(setCookie).contains("Max-Age=0");
    }
}
