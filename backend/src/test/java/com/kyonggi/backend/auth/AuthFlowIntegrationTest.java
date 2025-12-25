package com.kyonggi.backend.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyonggi.backend.auth.signup.service.SignupMailSender;
import com.kyonggi.backend.auth.signup.support.OtpCodeGenerator;
import com.kyonggi.backend.auth.token.repo.RefreshTokenRepository;

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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ActiveProfiles("test")            // application-test.yml을 쓰도록 강제(테스트 DB/설정 분리)
@SpringBootTest                    // 실제 Spring 컨텍스트를 올려서 "통합 테스트"로 돌림
@AutoConfigureMockMvc              // 톰캣 띄우지 않고 MockMvc로 HTTP 호출 흉내
class AuthFlowIntegrationTest {

    private static final String FIXED_OTP = "123456";      // OTP를 고정값으로 만들어 테스트를 결정론적으로
    private static final String PASSWORD = "Abcdef12!";    // 정책 통과하는 강한 비번

    // OTP 생성과 메일 발송은 외부/랜덤 요소라 테스트에선 고정/차단하는 게 실무적
    // - OtpCodeGenerator: 랜덤이라 고정해야 함
    // - SignupMailSender: 실제 메일 발송하면 느리고 불안정 -> mock으로 "호출됐는지만" 확인
    @MockitoBean OtpCodeGenerator otpCodeGenerator;
    @MockitoBean SignupMailSender signupMailSender;

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;
    @Autowired RefreshTokenRepository refreshTokenRepository;
    @Autowired Clock clock;        
    @Autowired JdbcTemplate jdbc;   

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM refresh_tokens");
        jdbc.update("DELETE FROM email_otp");
        jdbc.update("DELETE FROM users");

        // OTP는 항상 FIXED_OTP가 나오게 해서, verify 단계에서 항상 성공하게 만든다
        Mockito.when(otpCodeGenerator.generate6Digits()).thenReturn(FIXED_OTP);
    }

    @AfterAll
    void afterAll() {
        jdbc.update("DELETE FROM refresh_tokens");
        jdbc.update("DELETE FROM email_otp");
        jdbc.update("DELETE FROM users");
    }

    @Test // "회원가입 성공 → 로그인(rememberMe=true) 성공 → refresh 쿠키가 내려가고 DB에 refresh row가 저장된다"
    void signup_then_login_rememberMe_true_sets_cookie_and_inserts_refresh_row() throws Exception {
        
        String email = randomKyonggiEmail();
        String nickname = randomNickname();

        // 1) OTP 요청: 204 기대 = "/auth/signup/otp/request"
        mvc.perform(post("/auth/signup/otp/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new SignupOtpRequest(email))))
                .andExpect(status().isNoContent());

        // 메일 발송이 "정상적으로 호출됐는지" 검증(외부효과)
        verify(signupMailSender).sendOtp(email, FIXED_OTP);

        // 2) OTP 검증: 고정 OTP로 성공(204) = "/auth/signup/otp/verify"
        mvc.perform(post("/auth/signup/otp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new SignupOtpVerifyRequest(email, FIXED_OTP))))
                .andExpect(status().isNoContent());

        // 3) 회원가입 완료: 2xx(보통 201) = "/auth/signup/complete"
        mvc.perform(post("/auth/signup/complete")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new SignupCompleteRequest(email, PASSWORD, PASSWORD, nickname))))
                .andExpect(status().is2xxSuccessful());

        // 4) 로그인 rememberMe=true
        // 기대:
        // - 200 OK
        // - accessToken은 JSON body로 내려옴
        // - refresh token은 HttpOnly 쿠키(Set-Cookie)로 내려옴
        // - rememberMe=true면 Max-Age(=영속 쿠키)가 있어야 함
        var result = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new LoginRequest(email, PASSWORD, true))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(header().string("Set-Cookie", Matchers.containsString("KG_REFRESH=")))
                .andExpect(header().string("Set-Cookie", Matchers.containsString("HttpOnly")))
                .andExpect(header().string("Set-Cookie", Matchers.containsString("Max-Age=")))
                .andReturn();

        // 5) 쿠키 원문(raw)을 파싱하고, sha256으로 해시해서 DB의 token_hash랑 매칭되는지 확인
        String setCookie = result.getResponse().getHeader("Set-Cookie");
        assertThat(setCookie).isNotBlank();

        String refreshRaw = extractCookieValue(setCookie, "KG_REFRESH");
        String hash = sha256Hex(refreshRaw);

        // 6) DB 검증(실무적으로 제일 중요한 부분)
        // - revoked_at은 null이어야 함(로그인 직후 active 세션)
        // - expires_at은 현재보다 미래(만료 안 됨)
        // - remember_me는 true로 저장되어야 함(정책 반영)
        var rt = refreshTokenRepository.findByTokenHash(hash).orElseThrow();
        assertThat(rt.getRevokedAt()).isNull();
        assertThat(rt.getExpiresAt()).isAfter(java.time.LocalDateTime.now(clock));
        assertThat(rt.isRememberMe()).isTrue();
    }

    @Test
    void login_wrong_password_returns_401_and_no_cookie() throws Exception {
        // 로그인 실패 시 "쿠키가 절대 발급되면 안 된다"를 보장한다.

        String email = randomKyonggiEmail();
        String nickname = randomNickname();

        // 회원가입까지는 정상 완료시켜 로그인 시도 기반을 만든다
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

        // ✅ wrong password → 401
        // ✅ 그리고 Set-Cookie 헤더가 없어야 함 (refresh 쿠키 미발급 보장)
        mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(new LoginRequest(email, "WRONGPW1!", true))))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void login_rememberMe_false_sets_session_cookie_without_max_age() throws Exception {
        // ✅ 이 테스트의 목표:
        // rememberMe=false면 "세션 쿠키"로 나가야 한다.
        // 즉, Set-Cookie는 내려가되 Max-Age가 없어야 브라우저 종료 시 삭제된다.

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

        // ✅ rememberMe=false 정책: Max-Age가 없어야 세션쿠키
        assertThat(setCookie).doesNotContain("Max-Age=");
    }

    // payloads
    // ✅ 테스트 클래스 내부 record로 DTO를 간단히 정의해서,
    // 실제 프로덕션 DTO에 의존하지 않고 "API 계약"만 검증하는 방식.
    record SignupOtpRequest(String email) {}
    record SignupOtpVerifyRequest(String email, String code) {}
    record SignupCompleteRequest(String email, String password, String passwordConfirm, String nickname) {}
    record LoginRequest(String email, String password, Boolean rememberMe) {}

    private static String randomKyonggiEmail() {
        // ✅ 유니크 보장: 유니크 제약(email unique) 때문에 테스트가 깨지지 않게 함
        return "test" + System.currentTimeMillis() + "@kyonggi.ac.kr";
    }

    private static String randomNickname() {
        // ✅ 유니크 보장: nickname unique
        return ("t_" + Long.toString(System.nanoTime(), 36)).substring(0, 10);
    }

    private static String extractCookieValue(String setCookieHeader, String cookieName) {
        // ✅ Set-Cookie에서 "쿠키 값(raw)"만 추출
        // (브라우저처럼 파싱 라이브러리 써도 되지만, 테스트에선 가벼운 파서로 충분)
        String prefix = cookieName + "=";
        int start = setCookieHeader.indexOf(prefix);
        if (start < 0) throw new IllegalArgumentException("Cookie not found: " + cookieName);
        int valueStart = start + prefix.length();
        int end = setCookieHeader.indexOf(';', valueStart);
        if (end < 0) end = setCookieHeader.length();
        return setCookieHeader.substring(valueStart, end);
    }

    private static String sha256Hex(String raw) {
        // ✅ refresh raw는 DB에 저장 금지.
        // incoming raw를 sha256Hex로 변환해서 DB token_hash와 매칭되는지 검증하기 위한 헬퍼.
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
