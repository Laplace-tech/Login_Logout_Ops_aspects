package com.kyonggi.backend.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyonggi.backend.auth.signup.service.SignupMailSender;
import com.kyonggi.backend.auth.signup.support.OtpCodeGenerator;
import com.kyonggi.backend.auth.token.repo.RefreshTokenRepository;

import jakarta.servlet.http.Cookie;

@ActiveProfiles("test")
@SpringBootTest
@AutoConfigureMockMvc
class AuthRefreshIntegrationTest {

    // ✅ refresh 쿠키 이름을 상수화: 컨트롤러/테스트 간 계약을 명확히
    private static final String COOKIE_NAME = "KG_REFRESH";

    private static final String FIXED_OTP = "123456";
    private static final String PASSWORD = "Abcdef12!";
    private static final String REFRESH_PATH = "/auth/refresh";

    @MockitoBean OtpCodeGenerator otpCodeGenerator;
    @MockitoBean SignupMailSender signupMailSender;

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;
    @Autowired JdbcTemplate jdbc;
    @Autowired RefreshTokenRepository refreshTokenRepository;

    @BeforeEach
    void setUp() {
        // ✅ 테스트 독립성 보장: DB 초기화
        jdbc.update("DELETE FROM refresh_tokens");
        jdbc.update("DELETE FROM email_otp");
        jdbc.update("DELETE FROM users");

        // ✅ OTP를 고정해서 signup 흐름을 안정화
        Mockito.when(otpCodeGenerator.generate6Digits()).thenReturn(FIXED_OTP);
    }

    @AfterAll
    void afterAll() {
        jdbc.update("DELETE FROM refresh_tokens");
        jdbc.update("DELETE FROM email_otp");
        jdbc.update("DELETE FROM users");
    }
    
    @Test
    void refresh_success_rotates_token_and_revokes_old_row() throws Exception {
        // ✅ 이 테스트의 목표(실무 핵심):
        // refresh 호출 시 "rotation"이 일어난다:
        // - old refresh는 revoke 된다 (재사용 불가)
        // - new refresh가 새로 발급된다
        // - DB에는 revoke된 old row + 새 row가 공존(감사/추적 목적)
        // - accessToken은 재발급된다
        //
        // 이게 안되면: refresh 탈취/재사용 공격에 취약해진다.

        // given: signup + login(rememberMe=true)
        String email = randomKyonggiEmail();
        String nickname = randomNickname();
        signupAndComplete(email, nickname);

        var loginRes = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new LoginRequest(email, PASSWORD, true))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(header().string("Set-Cookie", Matchers.containsString(COOKIE_NAME + "=")))
                .andReturn();

        String loginSetCookie = loginRes.getResponse().getHeader("Set-Cookie");
        assertThat(loginSetCookie).isNotBlank();

        // ✅ login에서 받은 refresh(raw)
        // refresh raw는 DB 저장 금지이기 때문에, 테스트에서도 sha256Hex로 변환해서 DB를 조회한다.
        String refresh1Raw = extractCookieValue(loginSetCookie, COOKIE_NAME);
        String refresh1Hash = sha256Hex(refresh1Raw);

        long countBefore = refreshTokenRepository.count();

        // when: refresh 호출 (Cookie로 refresh1 전달)
        var refreshRes = mvc.perform(post(REFRESH_PATH)
                        .cookie(new Cookie(COOKIE_NAME, refresh1Raw)))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.accessToken").isString())
                // ✅ 새 refresh 쿠키가 내려와야 함
                .andExpect(header().string("Set-Cookie", Matchers.containsString(COOKIE_NAME + "=")))
                .andExpect(header().string("Set-Cookie", Matchers.containsString("HttpOnly")))
                // ✅ rememberMe=true면 Max-Age 유지(영속 쿠키)
                .andExpect(header().string("Set-Cookie", Matchers.containsString("Max-Age=")))
                .andReturn();

        String refreshSetCookie = refreshRes.getResponse().getHeader("Set-Cookie");
        assertThat(refreshSetCookie).isNotBlank();

        // ✅ 새 refresh(raw)은 old와 달라야 함(회전)
        String refresh2Raw = extractCookieValue(refreshSetCookie, COOKIE_NAME);
        assertThat(refresh2Raw).isNotEqualTo(refresh1Raw);

        String refresh2Hash = sha256Hex(refresh2Raw);

        // then: DB에서 old는 revoked, new는 active
        // - revoke는 "재사용 방지"의 핵심
        var oldRow = refreshTokenRepository.findByTokenHash(refresh1Hash).orElseThrow();
        assertThat(oldRow.getRevokedAt()).isNotNull();

        var newRow = refreshTokenRepository.findByTokenHash(refresh2Hash).orElseThrow();
        assertThat(newRow.getRevokedAt()).isNull();

        // ✅ rotate 정책을 "revoke old + insert new"로 잡았기 때문에
        // row 수는 1개 증가해야 한다.
        assertThat(refreshTokenRepository.count()).isEqualTo(countBefore + 1);
    }

    @Test
    void refresh_reuse_of_old_token_returns_401() throws Exception {
        // ✅ 이 테스트의 목표(보안 핵심):
        // rotation 된 이후 old refresh를 "다시" 쓰면 401이 나와야 한다.
        // 즉, 재사용 공격을 방어한다.

        // given: signup + login
        String email = randomKyonggiEmail();
        String nickname = randomNickname();
        signupAndComplete(email, nickname);

        var loginRes = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new LoginRequest(email, PASSWORD, true))))
                .andExpect(status().isOk())
                .andExpect(header().string("Set-Cookie", Matchers.containsString(COOKIE_NAME + "=")))
                .andReturn();

        String loginSetCookie = loginRes.getResponse().getHeader("Set-Cookie");
        String refresh1Raw = extractCookieValue(loginSetCookie, COOKIE_NAME);

        // when: refresh 1회 성공(=rotation 발생)
        mvc.perform(post(REFRESH_PATH)
                        .cookie(new Cookie(COOKIE_NAME, refresh1Raw)))
                .andExpect(status().isOk());

        // then: 같은 refresh1을 다시 쓰면 401 (재사용 탐지)
        mvc.perform(post(REFRESH_PATH)
                        .cookie(new Cookie(COOKIE_NAME, refresh1Raw)))
                .andExpect(status().isUnauthorized());
    }

    // ---- helpers ----

    private void signupAndComplete(String email, String nickname) throws Exception {
        // ✅ refresh 테스트의 핵심은 refresh이므로,
        // signup/login은 헬퍼로 숨겨서 테스트 본문이 읽기 쉬워짐(Given/When/Then)
        mvc.perform(post("/auth/signup/otp/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new SignupOtpRequest(email))))
                .andExpect(status().isNoContent());

        mvc.perform(post("/auth/signup/otp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new SignupOtpVerifyRequest(email, FIXED_OTP))))
                .andExpect(status().isNoContent());

        mvc.perform(post("/auth/signup/complete")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new SignupCompleteRequest(email, PASSWORD, PASSWORD, nickname))))
                .andExpect(status().is2xxSuccessful());
    }

    // ✅ 테스트 내부 payload record:
    // 실제 DTO에 종속시키지 않고 "API 계약" 중심으로 테스트를 유지하는 장점이 있다.
    record SignupOtpRequest(String email) {}
    record SignupOtpVerifyRequest(String email, String code) {}
    record SignupCompleteRequest(String email, String password, String passwordConfirm, String nickname) {}
    record LoginRequest(String email, String password, Boolean rememberMe) {}

    private static String randomKyonggiEmail() {
        return "test" + System.currentTimeMillis() + "@kyonggi.ac.kr";
    }

    private static String randomNickname() {
        return ("t_" + Long.toString(System.nanoTime(), 36)).substring(0, 10);
    }

    private static String extractCookieValue(String setCookieHeader, String cookieName) {
        // ✅ Set-Cookie 문자열에서 쿠키 값만 추출
        String prefix = cookieName + "=";
        int start = setCookieHeader.indexOf(prefix);
        if (start < 0) throw new IllegalArgumentException("Cookie not found: " + cookieName);

        int valueStart = start + prefix.length();
        int end = setCookieHeader.indexOf(';', valueStart);
        if (end < 0) end = setCookieHeader.length();

        return setCookieHeader.substring(valueStart, end);
    }

    private static String sha256Hex(String raw) {
        // ✅ refresh raw는 DB에 저장하지 않기 때문에,
        // raw -> sha256Hex로 변환해서 DB token_hash를 조회한다.
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(dig.length * 2);
            for (byte b : dig) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
