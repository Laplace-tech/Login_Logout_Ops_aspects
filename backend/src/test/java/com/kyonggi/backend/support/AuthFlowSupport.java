package com.kyonggi.backend.support;

import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.kyonggi.backend.support.AuthHttpSupport.LoginResult;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.http.Cookie;

// AuthFlowSupport = "성공 플로우"를 짧게 만드는 고수준(HIGH-LEVEL) 유틸
public final class AuthFlowSupport {
    private AuthFlowSupport() {}

    /**
     * 로그인 성공을 기대하는 헬퍼 메서드
     *  - POST: /auth/login
     *  - 200 OK + JSON 반환을 강제
     *  - accessToken(body) + refreshToken(Set-Cookie)  추출해서 LoginResult로 반환
     */
    public static AuthHttpSupport.LoginResult loginOk(
            MockMvc mvc, 
            String email, 
            String password, 
            boolean rememberMe
    ) throws Exception {

        MvcResult res = AuthHttpSupport.performLogin(mvc, email, password, rememberMe)
                            .andExpect(status().isOk())
                            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                            .andReturn();

        String accessToken = AuthHttpSupport.readJson(res).get("accessToken").asText();
        List<String> setCookieHeaders = res.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        String refreshRaw = AuthHttpSupport.extractCookieValue(setCookieHeaders, AuthHttpSupport.REFRESH_COOKIE);

        return new LoginResult(accessToken, refreshRaw, setCookieHeaders);
    }

    /**
     * refresh 성공을 기대하는 헬퍼
     *
     * - /auth/refresh 호출(쿠키 포함)
     * - 200 OK + JSON 반환을 강제
     * - 새 accessToken + 새 refreshRaw(Set-Cookie) 추출해서 RefreshResult로 반환
     */
    public static AuthHttpSupport.RefreshResult refreshOk(MockMvc mvc, String refreshRaw) throws Exception {
 
        MvcResult res = AuthHttpSupport.performRefresh(
                        mvc, 
                        new Cookie(AuthHttpSupport.REFRESH_COOKIE, refreshRaw)
                    )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andReturn();

        String accessToken = AuthHttpSupport.readJson(res).get("accessToken").asText();
        List<String> setCookieHeaders = res.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        String newRefreshRaw = AuthHttpSupport.extractCookieValue(setCookieHeaders, AuthHttpSupport.REFRESH_COOKIE);

        return new AuthHttpSupport.RefreshResult(accessToken, newRefreshRaw, setCookieHeaders);
    }
}
