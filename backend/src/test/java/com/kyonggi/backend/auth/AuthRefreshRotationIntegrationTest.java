package com.kyonggi.backend.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
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
 * Refresh Token 로테이션 정책이 제대로 동작하는지 통합 테스트로 검증한다.
 * 
 * - 로그인하면 refresh 토큰이 쿠키로 내려오고 DB에는 hash가 저장된다
 * - /auth/refresh 호출 시, 기존 refresh는 REVOKED 처리되고(ROTATED) 
 *    새로운 refresh와 access 토큰을 발급해서 각각 쿠키와 바디로 내려준다.
 * - refresh 쿠키 없거나, unknown token, 재사용(reuse) 등 에러 처리도 검증한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("[Auth][Refresh] 리프레시 토큰 로테이션 통합 테스트")
class AuthRefreshRotationIntegrationTest extends AbstractAuthIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired TokenHashUtils tokenHashUtils;

    @Test 
    @DisplayName("로그인: refresh 쿠키 발급 + DB에는 refresh 해시 저장(세션 쿠키 정책)")
    void login_saves_refreshToken_hash_in_db_and_sets_cookie() throws Exception {
        // 로그인 객체 반환 (rememberMe = false)
        LoginResult login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, false); 

        // 응답으로 Refresh, Access 토큰 둘 다 있어야 함
        assertThat(login.refreshRaw()).isNotBlank();
        assertThat(login.accessToken()).isNotBlank();

        // DB에는 리프레쉬 토큰의 원문이 아니라 "hash"로 저장되어야 함
        String hash = tokenHashUtils.sha256Hex(login.refreshRaw());
        Optional<RefreshToken> saved = refreshTokenRepository.findByTokenHash(hash);

        // 저장됨 + revoked 아님 + rememberMe 아님
        assertThat(saved).isPresent();     
        assertThat(saved.get().isRevoked()).isFalse();
        assertThat(saved.get().isRememberMe()).isFalse();

        // Set-Cookie 정책 검증 (HttpOnly/Path/SameSite/Max-Age 없음)
        String setCookieLine = AuthTestSupport.findSetCookieLine(login.setCookieHeaders(), AuthTestSupport.REFRESH_COOKIE);
        AuthTestSupport.assertRefreshCookiePolicy(setCookieLine, false);
    }

    @Test
    @DisplayName("로그인(rememberMe): persistent refresh 쿠키(Max-Age) + DB rememberMe=true 저장")
    void login_with_rememberMe_sets_persistent_cookie_and_db_flag() throws Exception {
        // 로그인 요청 (rememberMe = true)
        LoginResult login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, true);

        // 쿠키 정책은 persistent여야 하므로 Max-Age가 있어야 함
        String setCookieLine = AuthTestSupport.findSetCookieLine(login.setCookieHeaders(), AuthTestSupport.REFRESH_COOKIE);
        AuthTestSupport.assertRefreshCookiePolicy(setCookieLine, true);

        // DB에도 rememberMe 플래그가 true로 저장되어야 함
        String hash = tokenHashUtils.sha256Hex(login.refreshRaw());
        Optional<RefreshToken> saved = refreshTokenRepository.findByTokenHash(hash);

        assertThat(saved).isPresent();
        assertThat(saved.get().isRememberMe()).isTrue();
        assertThat(saved.get().isRevoked()).isFalse();
    }

    @Test
    @DisplayName("리프레시: 토큰 로테이션 수행(새 refresh 발급) + 기존 refresh ROTATED로 폐기")
    void refresh_rotates_token_and_revokes_old() throws Exception {
        // 로그인해서 old refresh를 얻는다
        LoginResult login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, false);
        String oldRaw = login.refreshRaw();
        String oldHash = tokenHashUtils.sha256Hex(oldRaw);

        // old 토큰이 DB에 저장되어 있어야 함
        assertThat(refreshTokenRepository.findByTokenHash(oldHash)).isPresent();

        // POST: /auth/refresh 호출 (쿠키로 old refresh 전달)
        MvcResult refreshRes = mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(AuthTestSupport.REFRESH_COOKIE, oldRaw)))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith("application/json"))
                    .andExpect(jsonPath("$.accessToken").isNotEmpty())
                    .andExpect(result -> AuthTestSupport.assertHasCookie(
                        result.getResponse().getHeaders(HttpHeaders.SET_COOKIE),
                        AuthTestSupport.REFRESH_COOKIE
                    ))
                .andReturn();

        // 응답 Set-Cookie에서 new refresh 값을 추출
        List<String> setCookies = refreshRes.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        String newRaw = AuthTestSupport.extractCookieValue(setCookies, AuthTestSupport.REFRESH_COOKIE);

        // new refresh는 비어있으면 안 되고 old와 달라야 함(= 로테이션)
        assertThat(newRaw).isNotBlank();
        assertThat(newRaw).isNotEqualTo(oldRaw);

        // old 토큰은 revoked 처리되어야 함 + reason=ROTATED
        var oldRowAfter = refreshTokenRepository.findByTokenHash(oldHash);
        assertThat(oldRowAfter).isPresent();
        assertThat(oldRowAfter.get().isRevoked()).isTrue();
        assertThat(oldRowAfter.get().getRevokeReason()).isEqualTo("ROTATED");

        // new 토큰은 DB에 저장되어 있어야 하고 revoked=false
        String newHash = tokenHashUtils.sha256Hex(newRaw);
        var newRow = refreshTokenRepository.findByTokenHash(newHash);
        assertThat(newRow).isPresent();
        assertThat(newRow.get().isRevoked()).isFalse();
    }

    @Test
    @DisplayName("리프레시: 쿠키 없음 → 401 REFRESH_INVALID")
    void refresh_without_cookie_returns_refresh_invalid() throws Exception {
        // 쿠키 없이 refresh 호출 => refresh 토큰이 없으므로 401 + REFRESH_INVALID
        mvc.perform(post("/auth/refresh"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.code").value("REFRESH_INVALID"));
    }

    @Test
    @DisplayName("리프레시: 미발급 refresh 토큰 → 401 REFRESH_INVALID")
    void refresh_with_unknown_token_returns_refresh_invalid() throws Exception {
        // 서버가 발급한 적 없는 refresh 토큰으로 호출 => 401 + REFRESH_INVALID
        mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(AuthTestSupport.REFRESH_COOKIE, "definitely-not-issued-by-server")))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.code").value("REFRESH_INVALID"));
    }

    @Test
    @DisplayName("리프레시: 로테이션 후 구 refresh 재사용 시도 → 401 REFRESH_REUSED")
    void refresh_reusing_old_token_is_blocked() throws Exception {
        // 로그인해서 old refresh 획득
        var login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, false);
        String oldRaw = login.refreshRaw();

        // 첫 refresh는 성공 (old -> new 로테이션)
        mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(AuthTestSupport.REFRESH_COOKIE, oldRaw)))
                .andExpect(status().isOk());
        
        // old refresh를 재사용하면 차단되어야 함 (REFRESH_REUSED)
        mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(AuthTestSupport.REFRESH_COOKIE, oldRaw)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_REUSED"));
    }

    @Test
    @DisplayName("리프레시: 로테이션 후에도 rememberMe 정책 유지(Max-Age 유지 + DB 플래그 유지)")
    void refresh_rotation_preserves_rememberMe_policy() throws Exception {
        // rememberMe=true 로그인 -> persistent refresh 발급
        var login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, true);
        String oldRaw = login.refreshRaw();

        // POST: /auth/refresh 호출
        var refreshRes = mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(AuthTestSupport.REFRESH_COOKIE, oldRaw)))
                .andExpect(status().isOk())
                .andExpect(result -> AuthTestSupport.assertHasCookie(
                        result.getResponse().getHeaders(HttpHeaders.SET_COOKIE),
                        AuthTestSupport.REFRESH_COOKIE
                ))
                .andReturn();

        // 새 refresh 쿠키도 persistent(Max-Age 유지)여야 함
        var setCookies = refreshRes.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        String line = AuthTestSupport.findSetCookieLine(setCookies, AuthTestSupport.REFRESH_COOKIE);
        AuthTestSupport.assertRefreshCookiePolicy(line, true);

        // DB에도 rememberMe=true가 유지되어야 함
        String newRaw = AuthTestSupport.extractCookieValue(setCookies, AuthTestSupport.REFRESH_COOKIE);
        String newHash = tokenHashUtils.sha256Hex(newRaw);

        var newRow = refreshTokenRepository.findByTokenHash(newHash);
        assertThat(newRow).isPresent();
        assertThat(newRow.get().isRememberMe()).isTrue();
        assertThat(newRow.get().isRevoked()).isFalse();
    }
}
