package com.kyonggi.backend.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


/**
 * <참고>: Set-Cookie 포맷
 * - Set-Cookie: <cookie-name>=<cookie-value>; <attribute1>; <attribute2>; ....
 * 
 * LoginResult login(MockMvc mvc, String email, String password, boolean rememberMe): 로그인 메서드
 * JsonNode readJson(MvcResult res) throws Exception                                : body를 파싱하여 JSON으로 변환
 * String extractCookieValue(List<String> setCookieHeaders, String cookieName)      : cookie-name 기반으로 cookie-value 추출
 * String findSetCookieLine(List<String> setCookieHeaders, String cookieName)       : cookie-name 기반으로 해당 라인 전체 추출
 * void assertHasCookie(List<String> setCookieHeaders, String cookieName)           : 해당 쿠키를 가지고 있는지 검증
 * void assertRefreshCookiePolicy(String setCookieLine, boolean persistentExpected) : Refresh 쿠키의 보안/정책 설정이 기대한 대로 내려왔는지 검사
 */
public final class AuthTestSupport {
    private AuthTestSupport() {}

    private static final ObjectMapper om = new ObjectMapper(); 
    public static final String REFRESH_COOKIE = "KG_REFRESH"; // application-test.yml의 app.auth.refresh.cookie-name과 맞춰야 함

    /**
     * LoginResult(DTO): 로그인 결과를 테스트에서 쓰기 편하게 묶은 record
     * - accessToken: 바디(JSON)로 내려온 access 토큰
     * - refreshRaw: Set-Cookie에 담긴 refresh 토큰의 "값" 부분(원문) (= ...)
     * - setCookieHeaders: 전체 Set-Cookie 헤더 리스트 (쿠키 정책 검사할 때 사용)
     */
    public record LoginResult(
        String accessToken, 
        String refreshRaw, 
        List<String> setCookieHeaders
    ) {}


    /**
     * HTTP 응답 예시 ("Set-Cookie 헤더는 여러 개"일 수 있음)
     * ============================================================================================
     * HTTP/1.1 200 OK                                                                            ㅣ
     * Set-Cookie: KG_REFRESH=eyJhbGciOiJIUzI1NiJ9.abc.def; Path=/auth; HttpOnly; SameSite=Lax    ㅣ
     * Content-Type: application/json                                                             ㅣ
     * .                                                                                          ㅣ
     * .                                                                                          ㅣ
     * {"accessToken":"eyJhbGzY3MT...4PKGjIiMZ_SZ3KiJ6yYrToZ3Os"}                                 ㅣ
     * ============================================================================================
     * 
     * 자바에서 추출하는 값: (그대로 LoginResult로 만들어 반환) 
     * - accessToken = "eyJhbGzY3MT...4PKGjIiMZ_SZ3KiJ6yYrToZ3Os"
     * - setCookies = List.of("KG_REFRESH=eyJhbGciOiJIUzI1NiJ9.abc.def; Path=/auth; HttpOnly; SameSite=Lax");
     * - refreshRaw = "eyJhbGciOiJIUzI1NiJ9.abc.def";
     */
    public static LoginResult login(MockMvc mvc, String email, String password, boolean rememberMe) throws Exception {
        MvcResult res = mvc.perform(post("/auth/login")
                        .contentType("application/json")
                        .content("""
                                {"email":"%s","password":"%s","rememberMe":%s}
                                """.formatted(email, password, rememberMe)))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json")) 
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE))
                .andReturn();

        String accessToken = readJson(res).get("accessToken").asText();

        List<String> setCookies = res.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        String refreshRaw = extractCookieValue(setCookies, REFRESH_COOKIE);

        return new LoginResult(accessToken, refreshRaw, setCookies);
    }


    // MvcResult 응답 body(String)를 JSON으로 파싱해서 JsonNode로 반환
    public static JsonNode readJson(MvcResult res) throws Exception {
        return om.readTree(res.getResponse().getContentAsString());
    }

    /** findSetCookieLine 기반으로 값만 추출 (정규식보다 안전/디버깅 쉬움) */
    public static String extractCookieValue(List<String> setCookieHeaders, String cookieName) {
        String line = findSetCookieLine(setCookieHeaders, cookieName);

        /**
         * line = "KG_REFRESH=aaa.bbb.ccc; Path=/auth; HttpOnly; SameSite=Lax" 
         * first = "KG_REFRESH=aaa.bbb.ccc"
         * first.substring = "aaa.bbb.ccc"
         */
        String first = line.split(";", 2)[0];
        int idx = first.indexOf('=');
        if (idx < 0) throw new IllegalStateException("Malformed Set-Cookie: " + line);

        return first.substring(idx + 1);
    }

    /** 
     * 다중 Set-Cookie 환경에서도 안정적으로 특정 쿠키 라인 찾기:
     * 
     * [예시]
     * setCookies = List.of(
     *      "KG_REFRESH=aaa.bbb.ccc; Path=/auth; HttpOnly; SameSite=Lax",
     *      "JSESSIONID=123456789; Path=/; HttpOnly"
     * ); 
     * cookieName = "KG_REFRESH"
     */
    public static String findSetCookieLine(List<String> setCookieHeaders, String cookieName) {
        assertThat(setCookieHeaders)
                .as("Set-Cookie header missing")
                .isNotNull()
                .isNotEmpty();

        // "COOKIE_NAME="로 시작하는 라인 찾기 (가장 안정적)
        return setCookieHeaders.stream()
                .filter(h -> h != null && h.startsWith(cookieName + "="))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Set-Cookie line for " + cookieName + " not found. headers=" + setCookieHeaders
                ));
    }

    /** Set-Cookie 헤더 리스트에 refresh 쿠키가 있는지 검증 (MockMvc header().string() 대체) */
    public static void assertHasCookie(List<String> setCookieHeaders, String cookieName) {
        assertThat(setCookieHeaders)
                .as("Set-Cookie should contain " + cookieName)
                .isNotNull()
                .anyMatch(h -> h != null && h.startsWith(cookieName + "="));
    }

    /**
     * Refresh 쿠키의 보안/정책 설정이 기대한 대로 내려왔는지 검사
     */
    public static void assertRefreshCookiePolicy(String setCookieLine, boolean persistentExpected) {
        assertThat(setCookieLine).contains("HttpOnly");
        assertThat(setCookieLine).contains("Path=/auth");
        assertThat(setCookieLine).contains("SameSite=Lax");

        if (persistentExpected) {
            assertThat(setCookieLine).contains("Max-Age=");
        } else {
            assertThat(setCookieLine).doesNotContain("Max-Age=");
        }
    }
}
