package com.kyonggi.backend.auth;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Auth 통합테스트에서 반복되는 "로그인/쿠키 추출/헤더 파싱" 로직을 모아둔 유틸.
 * - 테스트가 길어지는 걸 막고
 * - 쿠키/헤더 파싱 버그를 한 군데에서만 고치게 만든다.
 */
public final class AuthTestSupport {

    private AuthTestSupport() {}

    public record LoginResult(String accessToken, String refreshRaw, List<String> setCookieHeaders) {}

    /** /auth/login 호출 -> accessToken + refresh(cookie) 추출 */
    public static LoginResult login(MockMvc mvc, String email, String password, boolean rememberMe) throws Exception {
        MvcResult res = mvc.perform(post("/auth/login")
                        .contentType("application/json")
                        .content("""
                                {"email":"%s","password":"%s","rememberMe":%s}
                                """.formatted(email, password, rememberMe)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE))
                .andReturn();

        String accessToken = res.getResponse().getContentAsString();
        // ObjectMapper 없이 jsonPath로 꺼내는 방법이 없어서 content로 읽고 정규식 쓰는 것도 가능하지만,
        // 여기선 "테스트가 명확"하게 각 테스트에서 ObjectMapper로 파싱하는 편이 더 낫다.
        // => 그래서 여기서는 accessToken을 바로 파싱하지 않고, 호출자가 ObjectMapper로 파싱해도 되지만
        // 이미 jsonPath 검증을 했으니 "빠른 파싱"을 위해 간단하게 정규식으로 뽑는다.
        String token = extractJsonStringField(accessToken, "accessToken");

        List<String> setCookies = res.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        String refreshRaw = extractCookieValue(setCookies, "KG_REFRESH");

        return new LoginResult(token, refreshRaw, setCookies);
    }

    /** Set-Cookie 헤더 여러 개 중에서 특정 쿠키 값만 안전하게 추출 */
    public static String extractCookieValue(List<String> setCookieHeaders, String cookieName) {
        if (setCookieHeaders == null || setCookieHeaders.isEmpty()) {
            throw new IllegalStateException("Set-Cookie header missing");
        }
        Pattern p = Pattern.compile("(^|;\\s*)" + Pattern.quote(cookieName) + "=([^;]+)");
        for (String h : setCookieHeaders) {
            Matcher m = p.matcher(h);
            if (m.find()) return m.group(2);
        }
        throw new IllegalStateException("Cookie " + cookieName + " not found. headers=" + setCookieHeaders);
    }

    /** 특정 쿠키의 Set-Cookie 라인(속성 포함)을 통째로 가져오기(옵션 검증용) */
    public static String findSetCookieLine(List<String> setCookieHeaders, String cookieName) {
        Pattern p = Pattern.compile("(^|;\\s*)" + Pattern.quote(cookieName) + "=([^;]+)");
        for (String h : setCookieHeaders) {
            if (p.matcher(h).find()) return h;
        }
        throw new IllegalStateException("Set-Cookie line for " + cookieName + " not found. headers=" + setCookieHeaders);
    }

    private static String extractJsonStringField(String json, String field) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        if (!m.find()) throw new IllegalStateException("JSON field not found: " + field + ", json=" + json);
        return m.group(1);
        
    }
}
