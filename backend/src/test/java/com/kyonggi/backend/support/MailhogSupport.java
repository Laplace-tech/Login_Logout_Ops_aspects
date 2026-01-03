package com.kyonggi.backend.support;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyonggi.backend.AbstractIntegrationTest;

public final class MailhogSupport {
    private MailhogSupport() {}

    private static final ObjectMapper om = new ObjectMapper();
    private static final HttpClient http = HttpClient.newHttpClient();
    private static final Pattern OTP_6 = Pattern.compile("\\b(\\d{6})\\b");

    /** ✅ Testcontainers 매핑 포트 기반 MailHog base URL */
    private static String baseUrl() {
        return "http://" + AbstractIntegrationTest.getMailhogHost() + ":" + AbstractIntegrationTest.getMailhogHttpPort();
    }

    /** MailHog 전체 메일 삭제 (Flow 테스트 전 @BeforeEach에서 호출) */
    public static void clearAll() throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl() + "/api/v1/messages"))
                .DELETE()
                .timeout(Duration.ofSeconds(3))
                .build();

        http.send(req, HttpResponse.BodyHandlers.discarding());
    }

    /** 특정 수신자에게 온 메일에서 6자리 OTP를 기다렸다가 반환 */
    public static String awaitOtpFor(String toEmail, Duration timeout) throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
        JsonNode lastRoot = null;

        while (System.nanoTime() < deadline) {
            HttpResponse<String> res = fetchV2Messages();
            if (res.statusCode() / 100 != 2) {
                Thread.sleep(200);
                continue;
            }

            JsonNode root = om.readTree(res.body());
            lastRoot = root;

            String otp = tryFindOtpFromRoot(root, toEmail);
            if (otp != null) return otp;

            Thread.sleep(200);
        }

        throw new AssertionError(
                "OTP email not found in MailHog for: " + toEmail +
                " (baseUrl=" + baseUrl() + ")\n" +
                "debug=" + summarize(lastRoot)
        );
    }

    private static HttpResponse<String> fetchV2Messages() throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl() + "/api/v2/messages?limit=50"))
                .GET()
                .timeout(Duration.ofSeconds(3))
                .build();

        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private static String tryFindOtpFromRoot(JsonNode root, String toEmail) {
        JsonNode items = root.get("items");
        if (items == null || !items.isArray()) return null;

        for (JsonNode item : items) {
            // ✅ 1) 수신자 필터: MailHog v2는 top-level "To"가 envelope 수신자임
            if (!recipientMatches(item, toEmail)) continue;

            // ✅ 2) subject + body + mime parts에서 OTP 탐색
            String subject = headerFirst(item, "Subject");
            String contentBody = safeText(item.at("/Content/Body"));
            String mimeBodies = collectMimeBodies(item);

            String haystack = (subject == null ? "" : subject) + "\n"
                    + (contentBody == null ? "" : contentBody) + "\n"
                    + (mimeBodies == null ? "" : mimeBodies);

            String otp = extractOtp(haystack);
            if (otp != null) return otp;
        }
        return null;
    }

    /** 수신자 매칭: (1) top-level To 배열 우선, (2) 헤더 To/Cc fallback, (3) 정보 없으면 통과 */
    private static boolean recipientMatches(JsonNode item, String email) {
        if (email == null || email.isBlank()) return true;

        String target = email.trim().toLowerCase(Locale.ROOT);

        // (1) top-level "To" (envelope recipients)
        JsonNode toArr = item.get("To");
        if (toArr != null && toArr.isArray() && toArr.size() > 0) {
            for (JsonNode r : toArr) {
                String addr = mailboxDomain(r);
                if (addr != null && addr.toLowerCase(Locale.ROOT).contains(target)) return true;
            }
            // To 정보가 "있는데" 매칭 실패면 확실히 다른 수신자 메일이므로 스킵
            return false;
        }

        // (2) fallback: Content.Headers.To / Cc (BCC는 원래 헤더에 안 들어가는 경우 많음)
        JsonNode headers = item.at("/Content/Headers");
        if (headers != null && !headers.isMissingNode()) {
            if (containsInHeader(headers.get("To"), target)) return true;
            if (containsInHeader(headers.get("Cc"), target)) return true;

            // Headers.To가 "undisclosed" 같은 경우는 신뢰 못 하니 필터링 포기
            String toText = flattenHeader(headers.get("To"));
            if (toText != null && toText.toLowerCase(Locale.ROOT).contains("undisclosed")) {
                return true;
            }
        }

        // (3) 수신자 정보가 애매하면(=BCC/특이 케이스) 필터링하지 말고 통과
        return true;
    }

    private static String mailboxDomain(JsonNode recipientNode) {
        if (recipientNode == null || recipientNode.isMissingNode()) return null;
        String mailbox = safeText(recipientNode.get("Mailbox"));
        String domain = safeText(recipientNode.get("Domain"));
        if (mailbox == null || mailbox.isBlank()) return null;
        if (domain == null || domain.isBlank()) return mailbox;
        return mailbox + "@" + domain;
    }

    private static boolean containsInHeader(JsonNode headerNode, String targetLower) {
        if (headerNode == null || headerNode.isMissingNode()) return false;

        if (headerNode.isArray()) {
            for (JsonNode n : headerNode) {
                String s = safeText(n);
                if (s != null && s.toLowerCase(Locale.ROOT).contains(targetLower)) return true;
            }
            return false;
        }

        String s = safeText(headerNode);
        return s != null && s.toLowerCase(Locale.ROOT).contains(targetLower);
    }

    private static String flattenHeader(JsonNode headerNode) {
        if (headerNode == null || headerNode.isMissingNode()) return null;
        if (!headerNode.isArray()) return safeText(headerNode);

        StringBuilder sb = new StringBuilder();
        for (JsonNode n : headerNode) {
            String s = safeText(n);
            if (s != null && !s.isBlank()) sb.append(s).append(" ");
        }
        return sb.toString().trim();
    }

    /** Content.Headers에서 headerName 첫 값 */
    private static String headerFirst(JsonNode item, String headerName) {
        JsonNode node = item.at("/Content/Headers/" + headerName);
        if (node == null || node.isMissingNode()) return null;

        if (node.isArray()) {
            return node.size() > 0 ? safeText(node.get(0)) : null;
        }
        return safeText(node);
    }

    /** multipart 대비: /MIME/Parts[].Body 전부 긁어서 합치기 */
    private static String collectMimeBodies(JsonNode item) {
        JsonNode parts = item.at("/MIME/Parts");
        if (parts == null || parts.isMissingNode() || !parts.isArray() || parts.size() == 0) return "";

        List<String> bodies = new ArrayList<>();
        for (JsonNode p : parts) {
            String b = safeText(p.get("Body"));
            if (b != null && !b.isBlank()) bodies.add(b);

            // 혹시 depth가 더 들어가는 구조도 방어
            JsonNode innerParts = p.at("/MIME/Parts");
            if (innerParts != null && innerParts.isArray()) {
                for (JsonNode ip : innerParts) {
                    String ib = safeText(ip.get("Body"));
                    if (ib != null && !ib.isBlank()) bodies.add(ib);
                }
            }
        }

        return String.join("\n", bodies);
    }

    private static String extractOtp(String text) {
        if (text == null || text.isBlank()) return null;
        Matcher m = OTP_6.matcher(text);
        return m.find() ? m.group(1) : null;
    }

    private static String safeText(JsonNode node) {
        return (node == null || node.isMissingNode() || node.isNull()) ? null : node.asText("");
    }

    private static String summarize(JsonNode root) {
        if (root == null) return "null";

        JsonNode items = root.get("items");
        if (items == null || !items.isArray()) return "no items";

        int n = Math.min(items.size(), 5);
        StringBuilder sb = new StringBuilder();
        sb.append("items=").append(items.size()).append(", sample=").append(n).append("\n");

        for (int i = 0; i < n; i++) {
            JsonNode item = items.get(i);
            String subject = headerFirst(item, "Subject");
            sb.append("- subject=").append(subject).append(", to=").append(recipientsToString(item)).append("\n");
        }
        return sb.toString();
    }

    private static String recipientsToString(JsonNode item) {
        JsonNode toArr = item.get("To");
        if (toArr == null || !toArr.isArray() || toArr.size() == 0) return "[]";

        List<String> r = new ArrayList<>();
        for (JsonNode n : toArr) {
            String addr = mailboxDomain(n);
            if (addr != null) r.add(addr);
        }
        return r.toString();
    }
}
