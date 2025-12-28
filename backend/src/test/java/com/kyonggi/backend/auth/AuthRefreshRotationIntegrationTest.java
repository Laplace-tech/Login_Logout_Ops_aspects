package com.kyonggi.backend.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.repo.EmailOtpRepository;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.auth.token.repo.RefreshTokenRepository;
import com.kyonggi.backend.auth.token.support.TokenHashUtils;

import jakarta.servlet.http.Cookie;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthRefreshRotationIntegrationTest {

    @Autowired MockMvc mvc;

    @Autowired UserRepository userRepository;
    @Autowired RefreshTokenRepository refreshTokenRepository;
    @Autowired EmailOtpRepository emailOtpRepository;

    @Autowired PasswordEncoder passwordEncoder;
    @Autowired TokenHashUtils tokenHashUtils;

    private static final String EMAIL = "add28482848@kyonggi.ac.kr";
    private static final String PASSWORD = "28482848a!";
    private static final String NICKNAME = "Anna";

    private static final String REFRESH_COOKIE = "KG_REFRESH";

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        emailOtpRepository.deleteAll();
        userRepository.deleteAll();

        String pwHash = passwordEncoder.encode(PASSWORD);
        userRepository.save(User.create(EMAIL, pwHash, NICKNAME));
    }

    @AfterAll
    void afterAll() {
        refreshTokenRepository.deleteAll();
        emailOtpRepository.deleteAll();
        userRepository.deleteAll();
    }

    /** 로그인 성공 시 refresh token은 "원문은 쿠키", "해시는 DB"에 저장 */
    @Test
    void login_saves_refreshToken_hash_in_db_and_sets_cookie() throws Exception {
        var login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, false);

        assertThat(login.refreshRaw()).isNotBlank();
        assertThat(login.accessToken()).isNotBlank();

        String hash = tokenHashUtils.sha256Hex(login.refreshRaw());
        var saved = refreshTokenRepository.findByTokenHash(hash);

        assertThat(saved).isPresent();
        assertThat(saved.get().isRevoked()).isFalse();
        assertThat(saved.get().isRememberMe()).isFalse();

        // rememberMe=false이면 session cookie여서 Max-Age가 없어야 한다(정책상)
        String setCookieLine = AuthTestSupport.findSetCookieLine(login.setCookieHeaders(), REFRESH_COOKIE);
        assertThat(setCookieLine).contains("HttpOnly");
        assertThat(setCookieLine).contains("Path=/auth");
        assertThat(setCookieLine).contains("SameSite=Lax");
        assertThat(setCookieLine).doesNotContain("Max-Age=");
    }

    /** rememberMe=true면 쿠키에 Max-Age가 붙고 DB에도 remember_me=true로 저장 */
    @Test
    void login_with_rememberMe_sets_persistent_cookie_and_db_flag() throws Exception {
        var login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, true);

        String setCookieLine = AuthTestSupport.findSetCookieLine(login.setCookieHeaders(), REFRESH_COOKIE);
        assertThat(setCookieLine).contains("Max-Age="); // 지속 쿠키

        String hash = tokenHashUtils.sha256Hex(login.refreshRaw());
        var saved = refreshTokenRepository.findByTokenHash(hash);
        assertThat(saved).isPresent();
        assertThat(saved.get().isRememberMe()).isTrue();
        assertThat(saved.get().isRevoked()).isFalse();
    }

    /** refresh 호출 시: old revoke + new 발급 + access 재발급 */
    @Test
    void refresh_rotates_token_and_revokes_old() throws Exception {
        var login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, false);

        String oldRaw = login.refreshRaw();
        String oldHash = tokenHashUtils.sha256Hex(oldRaw);

        var oldRowBefore = refreshTokenRepository.findByTokenHash(oldHash);
        assertThat(oldRowBefore).isPresent();
        assertThat(oldRowBefore.get().isRevoked()).isFalse();

        var refreshRes = mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(REFRESH_COOKIE, oldRaw)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString(REFRESH_COOKIE + "=")))
                .andReturn();

        String newRaw = AuthTestSupport.extractCookieValue(
                refreshRes.getResponse().getHeaders(HttpHeaders.SET_COOKIE),
                REFRESH_COOKIE
        );

        assertThat(newRaw).isNotBlank();
        assertThat(newRaw).isNotEqualTo(oldRaw);

        // old는 revoked
        var oldRowAfter = refreshTokenRepository.findByTokenHash(oldHash);
        assertThat(oldRowAfter).isPresent();
        assertThat(oldRowAfter.get().isRevoked()).isTrue();
        assertThat(oldRowAfter.get().getRevokeReason()).isEqualTo("ROTATED");

        // new는 active
        String newHash = tokenHashUtils.sha256Hex(newRaw);
        var newRow = refreshTokenRepository.findByTokenHash(newHash);
        assertThat(newRow).isPresent();
        assertThat(newRow.get().isRevoked()).isFalse();
    }

    /** refresh에 쿠키가 없으면 컨트롤러에서 바로 REFRESH_INVALID */
    @Test
    void refresh_without_cookie_returns_refresh_invalid() throws Exception {
        mvc.perform(post("/auth/refresh"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_INVALID"));
    }

    /** 존재하지 않는 refresh 토큰이면 rotate에서 REFRESH_INVALID */
    @Test
    void refresh_with_unknown_token_returns_refresh_invalid() throws Exception {
        mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(REFRESH_COOKIE, "definitely-not-issued-by-server")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_INVALID"));
    }

    /** old 토큰 재사용은 차단(REFRESH_REUSED) */
    @Test
    void refresh_reusing_old_token_is_blocked() throws Exception {
        var login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, false);
        String oldRaw = login.refreshRaw();

        // 1회 refresh -> old는 revoke
        mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(REFRESH_COOKIE, oldRaw)))
                .andExpect(status().isOk());

        // 같은 old token 재사용 -> 차단
        mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(REFRESH_COOKIE, oldRaw)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_REUSED"));
    }

    /** rememberMe=true 세션은 rotate 후에도 rememberMe 유지 + 쿠키 Max-Age 유지 */
    @Test
    void refresh_rotation_preserves_rememberMe_policy() throws Exception {
        var login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, true);
        String oldRaw = login.refreshRaw();

        var refreshRes = mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(REFRESH_COOKIE, oldRaw)))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString(REFRESH_COOKIE + "=")))
                .andReturn();

        var setCookies = refreshRes.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        String line = AuthTestSupport.findSetCookieLine(setCookies, REFRESH_COOKIE);
        assertThat(line).contains("Max-Age="); // rememberMe=true 유지

        String newRaw = AuthTestSupport.extractCookieValue(setCookies, REFRESH_COOKIE);
        String newHash = tokenHashUtils.sha256Hex(newRaw);

        var newRow = refreshTokenRepository.findByTokenHash(newHash);
        assertThat(newRow).isPresent();
        assertThat(newRow.get().isRememberMe()).isTrue();
        assertThat(newRow.get().isRevoked()).isFalse();
    }
}