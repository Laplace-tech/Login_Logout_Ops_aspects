package com.kyonggi.backend.auth.signup;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.NestedTestConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.kyonggi.backend.auth.AbstractAuthIntegrationTest;
import com.kyonggi.backend.global.ErrorCode;
import com.kyonggi.backend.support.AuthFlowSupport;
import com.kyonggi.backend.support.AuthHttpSupport;
import com.kyonggi.backend.support.MailhogSupport;

/**
 * Signup OTP 관련 통합 테스트를 "한 파일"로 묶는다.
 * - Cooldown / DailyLimit / Flow 를 @Nested로 구획
 */
@DisplayName("[Auth][Signup][OTP] 통합 테스트")
@NestedTestConfiguration(NestedTestConfiguration.EnclosingConfiguration.INHERIT) // ✅ nested가 외부(Spring 설정/주입) 상속
class AuthSignupOtpIT extends AbstractAuthIntegrationTest {

    @Autowired
    MockMvc mvc;

    // Flow(회원가입 성공 루트)에서 쓰는 값
    private static final String NEW_EMAIL = "new_user_01@kyonggi.ac.kr";
    private static final String NEW_NICK = "Newbie_01";
    private static final String NEW_PW = "Abcdef12!";

    // 1) Cooldown
    @Nested
    @DisplayName("Cooldown")
    class Cooldown {

        @Test
        @DisplayName("연속 요청 → 429 OTP_COOLDOWN")
        void otp_cooldown_blocks_repeated_requests() throws Exception {
            String email = "cooldown_01@kyonggi.ac.kr";

            AuthHttpSupport.performSignupOtpRequest(mvc, email)
                    .andExpect(status().is2xxSuccessful());

            AuthHttpSupport.expectErrorWithCode(
                    AuthHttpSupport.performSignupOtpRequest(mvc, email),
                    ErrorCode.OTP_COOLDOWN);
        }
    }

    // 2) Daily limit (테스트 빠르게 돌리려고 limit 축소)
    @Nested
    @DisplayName("DailyLimit")
    @TestPropertySource(properties = {
            "app.otp.daily-send-limit=2",
            "app.otp.resend-cooldown-seconds=0",
            "app.otp.hmac-secret=01234567890123456789012345678901"
    })
    class DailyLimit {

        @Test
        @DisplayName("3번째 요청에서 429 OTP_DAILY_LIMIT")
        void otp_daily_limit_blocks_after_threshold() throws Exception {
            String email = "daily_01@kyonggi.ac.kr";

            AuthHttpSupport.performSignupOtpRequest(mvc, email).andExpect(status().is2xxSuccessful());
            AuthHttpSupport.performSignupOtpRequest(mvc, email).andExpect(status().is2xxSuccessful());
            AuthHttpSupport.expectErrorWithCode(
                    AuthHttpSupport.performSignupOtpRequest(mvc, email),
                    ErrorCode.OTP_DAILY_LIMIT);
        }
    }

    // 3) Full flow (MailHog 기반)
    @Nested
    @DisplayName("Flow")
    class Flow {

        @BeforeEach
        void clearMailhog() throws Exception {
            MailhogSupport.clearAll();
        }

        @Test
        @DisplayName("otp request: kyonggi 도메인 아니면 → 400 EMAIL_DOMAIN_NOT_ALLOWED")
        void otp_request_rejects_non_kyonggi_domain() throws Exception {
            AuthHttpSupport.expectErrorWithCode(
                    AuthHttpSupport.performSignupOtpRequest(mvc, "abc@gmail.com"),
                    ErrorCode.EMAIL_DOMAIN_NOT_ALLOWED);
        }

        @Test
        @DisplayName("otp verify: 요청 이력 없으면 → 400 OTP_NOT_FOUND")
        void otp_verify_without_request() throws Exception {
            AuthHttpSupport.expectErrorWithCode(
                    AuthHttpSupport.performSignupOtpVerify(mvc, NEW_EMAIL, "123456"),
                    ErrorCode.OTP_NOT_FOUND);
        }

        @Test
        @DisplayName("signup complete: OTP 미인증이면 → 400 OTP_NOT_VERIFIED")
        void signup_complete_requires_otp_verified() throws Exception {
            AuthHttpSupport.performSignupOtpRequest(mvc, NEW_EMAIL)
                    .andExpect(status().is2xxSuccessful());

            AuthHttpSupport.expectErrorWithCode(
                    AuthHttpSupport.performSignupComplete(mvc, NEW_EMAIL, NEW_PW, NEW_PW, NEW_NICK),
                    ErrorCode.OTP_NOT_VERIFIED);
        }

        @Test
        @DisplayName("happy path: request → (메일 OTP 추출) → verify → complete → login 가능")
        void signup_full_flow_success() throws Exception {
            AuthHttpSupport.performSignupOtpRequest(mvc, NEW_EMAIL)
                    .andExpect(status().is2xxSuccessful());

            String otp = MailhogSupport.awaitOtpFor(NEW_EMAIL, Duration.ofSeconds(15));
            assertThat(otp).matches("\\d{6}");

            AuthHttpSupport.performSignupOtpVerify(mvc, NEW_EMAIL, otp)
                    .andExpect(status().is2xxSuccessful());

            AuthHttpSupport.performSignupComplete(mvc, NEW_EMAIL, NEW_PW, NEW_PW, NEW_NICK)
                    .andExpect(status().is2xxSuccessful());

            var login = AuthFlowSupport.loginOk(mvc, NEW_EMAIL, NEW_PW, false);
            assertThat(login.accessToken()).isNotBlank();
            assertThat(login.refreshRaw()).isNotBlank();
        }
    }
}
