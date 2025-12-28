package com.kyonggi.backend.auth;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.repo.EmailOtpRepository;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.auth.token.repo.RefreshTokenRepository;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/**
 * /auth/me 통합 테스트
 * - SecurityFilterChain + JwtAuthenticationFilter + Controller/Service까지 실제로 엮어서 검증한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthMeIntegrationTest {

    @Autowired MockMvc mvc;

    @Autowired UserRepository userRepository;
    @Autowired RefreshTokenRepository refreshTokenRepository;
    @Autowired EmailOtpRepository emailOtpRepository;
    @Autowired PasswordEncoder passwordEncoder;

    private static final String EMAIL = "add28482848@kyonggi.ac.kr";
    private static final String PASSWORD = "28482848a!";
    private static final String NICKNAME = "Anna";

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        emailOtpRepository.deleteAll();
        userRepository.deleteAll();

        // 기본 유저 1명 준비 (me 응답 검증용)
        userRepository.save(User.create(EMAIL, passwordEncoder.encode(PASSWORD), NICKNAME));
    }

    /** 인증 헤더 없이 보호 리소스 접근 -> 401 (EntryPoint: AUTH_REQUIRED) */
    @Test
    void me_requires_auth() throws Exception {
        mvc.perform(get("/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTH_REQUIRED"));
    }

    /** Bearer 형식이 아니면 필터가 토큰을 무시 -> 결국 401 (AUTH_REQUIRED) */
    @Test
    void me_rejects_non_bearer_header_as_unauthenticated() throws Exception {
        mvc.perform(get("/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Basic abcdefg"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTH_REQUIRED"));
    }

    /** 토큰 형식 자체가 JWT가 아니면 -> 401 (JwtFilter: ACCESS_INVALID) */
    @Test
    void me_rejects_invalid_jwt() throws Exception {
        mvc.perform(get("/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("ACCESS_INVALID"));
    }

    /**
     * 실수 방지용 회귀 테스트:
     * refresh token(쿠키 값)을 access token으로 착각해서 Authorization에 넣으면 당연히 실패해야 한다.
     * (네가 방금 당했던 케이스)
     */
    @Test
    void me_rejects_refresh_token_string_used_as_access_token() throws Exception {
        var login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, false);
        String refreshRaw = login.refreshRaw();

        mvc.perform(get("/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + refreshRaw))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("ACCESS_INVALID"));
    }

    /** 정상 access token이면 /auth/me는 사용자 정보를 반환 */
    @Test
    void me_returns_user_info_when_access_token_valid() throws Exception {
        var login = AuthTestSupport.login(mvc, EMAIL, PASSWORD, false);
        String accessToken = login.accessToken();

        mvc.perform(get("/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(EMAIL)))
                .andExpect(jsonPath("$.userId").isNumber())
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.nickname").value(NICKNAME))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }
}
