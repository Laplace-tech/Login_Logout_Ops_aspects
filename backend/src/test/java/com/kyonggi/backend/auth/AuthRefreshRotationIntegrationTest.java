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

    @Test
    void login_saves_refreshToken_in_db() throws Exception {
        MvcResult res = mvc.perform(post("/auth/login")
                        .contentType("application/json")
                        .content("""
                                {"email":"%s","password":"%s","rememberMe":false}
                                """.formatted(EMAIL, PASSWORD))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                // Set-Cookie는 여러 개일 수 있지만, 최소한 KG_REFRESH는 포함돼야 함
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString(REFRESH_COOKIE + "=")))
                .andReturn();

        String refreshRaw = extractCookieValueFrom(res, REFRESH_COOKIE);
        assertThat(refreshRaw).isNotBlank();

        String hash = tokenHashUtils.sha256Hex(refreshRaw);
        var saved = refreshTokenRepository.findByTokenHash(hash);

        assertThat(saved).isPresent();
        assertThat(saved.get().isRevoked()).isFalse();
    }

    @Test
    void refresh_rotates_token_and_revokes_old() throws Exception {
        // 1) 로그인해서 refresh cookie 확보
        MvcResult loginRes = mvc.perform(post("/auth/login")
                        .contentType("application/json")
                        .content("""
                                {"email":"%s","password":"%s","rememberMe":false}
                                """.formatted(EMAIL, PASSWORD))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn();

        String oldRaw = extractCookieValueFrom(loginRes, REFRESH_COOKIE);
        String oldHash = tokenHashUtils.sha256Hex(oldRaw);

        var oldRowBefore = refreshTokenRepository.findByTokenHash(oldHash);
        assertThat(oldRowBefore).isPresent();
        assertThat(oldRowBefore.get().isRevoked()).isFalse();

        // 2) refresh 호출 -> 새 access + 새 refresh
        MvcResult refreshRes = mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(REFRESH_COOKIE, oldRaw))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString(REFRESH_COOKIE + "=")))
                .andReturn();

        String newRaw = extractCookieValueFrom(refreshRes, REFRESH_COOKIE);

        assertThat(newRaw).isNotBlank();
        assertThat(newRaw).isNotEqualTo(oldRaw);

        // 3) DB에서 old는 revoked, new는 active
        var oldRowAfter = refreshTokenRepository.findByTokenHash(oldHash);
        assertThat(oldRowAfter).isPresent();
        assertThat(oldRowAfter.get().isRevoked()).isTrue();
        assertThat(oldRowAfter.get().getRevokeReason()).isEqualTo("ROTATED");

        String newHash = tokenHashUtils.sha256Hex(newRaw);
        var newRow = refreshTokenRepository.findByTokenHash(newHash);
        assertThat(newRow).isPresent();
        assertThat(newRow.get().isRevoked()).isFalse();
    }

    @Test
    void refresh_reusing_old_token_is_blocked() throws Exception {
        // 로그인
        MvcResult loginRes = mvc.perform(post("/auth/login")
                        .contentType("application/json")
                        .content("""
                                {"email":"%s","password":"%s","rememberMe":false}
                                """.formatted(EMAIL, PASSWORD))
                )
                .andExpect(status().isOk())
                .andReturn();

        String oldRaw = extractCookieValueFrom(loginRes, REFRESH_COOKIE);

        // 1회 refresh -> old는 revoke
        mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(REFRESH_COOKIE, oldRaw))
                )
                .andExpect(status().isOk());

        // 같은 토큰 다시 사용 -> 401 + REFRESH_REUSED 기대
        mvc.perform(post("/auth/refresh")
                        .cookie(new Cookie(REFRESH_COOKIE, oldRaw))
                )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_REUSED"));
    }

    // ----------------- helpers -----------------

    /**
     * Set-Cookie 헤더가 여러 개여도 안전하게 cookieName 값만 찾아서 추출.
     */
    private static String extractCookieValueFrom(MvcResult res, String cookieName) {
        List<String> setCookies = res.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        if (setCookies == null || setCookies.isEmpty()) {
            throw new IllegalStateException("Set-Cookie header missing");
        }

        Pattern p = Pattern.compile("(^|;\\s*)" + Pattern.quote(cookieName) + "=([^;]+)");
        for (String headerValue : setCookies) {
            Matcher m = p.matcher(headerValue);
            if (m.find()) {
                return m.group(2);
            }
        }

        throw new IllegalStateException("Cookie " + cookieName + " not found. headers=" + setCookies);
    }
}
