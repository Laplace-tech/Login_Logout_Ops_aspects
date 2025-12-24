package com.kyonggi.backend.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyonggi.backend.auth.signup.service.SignupMailSender;
import com.kyonggi.backend.auth.signup.support.OtpCodeGenerator;
import com.kyonggi.backend.auth.token.repo.RefreshTokenRepository;
import org.hamcrest.Matchers;
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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ActiveProfiles("test")
@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowIntegrationTest {

    private static final String FIXED_OTP = "123456";
    private static final String PASSWORD = "Abcdef12!";

    @MockitoBean OtpCodeGenerator otpCodeGenerator;
    @MockitoBean SignupMailSender signupMailSender;

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;
    @Autowired RefreshTokenRepository refreshTokenRepository;
    @Autowired Clock clock;
    @Autowired JdbcTemplate jdbc;

    @BeforeEach
    void setUp() {
        // 테스트가 반복 실행돼도 안정적이게 DB 초기화 (FK 때문에 순서 중요)
        jdbc.update("DELETE FROM refresh_tokens");
        jdbc.update("DELETE FROM email_otp");
        jdbc.update("DELETE FROM users");

        Mockito.when(otpCodeGenerator.generate6Digits()).thenReturn(FIXED_OTP);
    }

    @Test
    void signup_then_login_rememberMe_true_sets_cookie_and_inserts_refresh_row() throws Exception {
        String email = randomKyonggiEmail();
        String nickname = randomNickname();

        mvc.perform(post("/auth/signup/otp/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new SignupOtpRequest(email))))
                .andExpect(status().isNoContent());

        verify(signupMailSender).sendOtp(email, FIXED_OTP);

        mvc.perform(post("/auth/signup/otp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new SignupOtpVerifyRequest(email, FIXED_OTP))))
                .andExpect(status().isNoContent());

        mvc.perform(post("/auth/signup/complete")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new SignupCompleteRequest(email, PASSWORD, PASSWORD, nickname))))
                .andExpect(status().is2xxSuccessful());

        var result = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new LoginRequest(email, PASSWORD, true))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(header().string("Set-Cookie", Matchers.containsString("KG_REFRESH=")))
                .andExpect(header().string("Set-Cookie", Matchers.containsString("HttpOnly")))
                .andExpect(header().string("Set-Cookie", Matchers.containsString("Max-Age=")))
                .andReturn();

        String setCookie = result.getResponse().getHeader("Set-Cookie");
        assertThat(setCookie).isNotBlank();

        String refreshRaw = extractCookieValue(setCookie, "KG_REFRESH");
        String hash = sha256Hex(refreshRaw);

        var rt = refreshTokenRepository.findByTokenHash(hash).orElseThrow();
        assertThat(rt.getRevokedAt()).isNull();
        assertThat(rt.getExpiresAt()).isAfter(java.time.LocalDateTime.now(clock));
        assertThat(rt.isRememberMe()).isTrue();
    }

    @Test
    void login_wrong_password_returns_401_and_no_cookie() throws Exception {
        String email = randomKyonggiEmail();
        String nickname = randomNickname();

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

        mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new LoginRequest(email, "WRONGPW1!", true))))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void login_rememberMe_false_sets_session_cookie_without_max_age() throws Exception {
        String email = randomKyonggiEmail();
        String nickname = randomNickname();

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

        var result = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new LoginRequest(email, PASSWORD, false))))
                .andExpect(status().isOk())
                .andExpect(header().string("Set-Cookie", Matchers.containsString("KG_REFRESH=")))
                .andReturn();

        String setCookie = result.getResponse().getHeader("Set-Cookie");
        assertThat(setCookie).isNotBlank();
        assertThat(setCookie).doesNotContain("Max-Age=");
    }

    // payloads
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
        String prefix = cookieName + "=";
        int start = setCookieHeader.indexOf(prefix);
        if (start < 0) throw new IllegalArgumentException("Cookie not found: " + cookieName);
        int valueStart = start + prefix.length();
        int end = setCookieHeader.indexOf(';', valueStart);
        if (end < 0) end = setCookieHeader.length();
        return setCookieHeader.substring(valueStart, end);
    }

    private static String sha256Hex(String raw) {
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
