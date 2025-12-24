package com.kyonggi.backend.auth.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyonggi.backend.auth.config.AuthProperties;

/**
 * Access Token(JWT) 담당 서비스
 * - 서버가 매번 DB를 조회하지 않고도(Stateless) 서명 검증만으로 "내가 발급한 토큰"인지 확인 가능
 * 
 * Access Token:
 * - 매 요청마다 서버에게 내 신원을 증명하는 짧은 수명 토큰
 * - 보통 프론트는 Authorization: Bearer <accessToken> 헤더에 담아 보냄
 * 
 * JWT 구조: header.payload.signature
 * - header: 알고리즘/타입 정보 (HS256, JWT)
 * - payload: 유저 정보(클레임: iss/sub/role/iat/exp 등)
 * - signature: header.payload를 서버 비밀키로 서명한 값(HMAC-SHA256)
 * 
 */
@Service
public class JwtService {

    // JSON 직렬화: Map -> JSON 문자열로 바꿀 때 사용
    private final ObjectMapper om = new ObjectMapper();
    private final Clock clock;
    private final AuthProperties props;

    public JwtService(Clock clock, AuthProperties props) {
        this.clock = clock;
        this.props = props;

        // 보통 최소 32 바이트 권장
        if (props.jwt().secret().getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("app.auth.jwt.secret must be at least 32 bytes");
        }
    }

    /**
     * =================
     * Access Token 발급
     * =================
     * 
     * 입력: userId, role
     * 출력: JWT 문자열(header.payload.signature)
     * 
     * 발급 흐름(무조건 암기 요구)
     * - header JSON 생성 ("alg": "HS256", "typ": "JWT")
     * - payload JSON 생성 (iat/exp 포함)
     * - Base64URL 인코딩 -> "header.payload" 서명 (HMAC-SHA256)
     * - signature까지 붙여서 반환
     */
    public String issueAccessToken(Long userId, String role) {
        try {
            // 1) JWT header: 어떤 알고리즘으로 서명했는지 + 타입
            String headerJson = om.writeValueAsString(Map.of("alg", "HS256", "typ", "JWT"));
            
            // 2) issued_at/expire: epoch seconds(초 단위)
            long now = Instant.now(clock).getEpochSecond();
            long exp = now + props.jwt().accessTtlSeconds();

            /**
             * 3) JWT payload(클레임): "이 토큰은 누구 것인지 판단"
             * - iss (issue): 발급자(우리 서비스)
             * - sub: 유저 식별자(여기선 userId)
             * - role: 권한(인가에 사용)
             * - iat(issue_at)/exp(expire): 발급/만료
             */
            String payloadJson = om.writeValueAsString(Map.of(
                    "iss", props.jwt().issuer(),
                    "sub", String.valueOf(userId),
                    "role", role,
                    "iat", now,
                    "exp", exp
            ));

            // 4) header/payload를 Base64URL 인코딩
            String header = b64Url(headerJson.getBytes(StandardCharsets.UTF_8));
            String payload = b64Url(payloadJson.getBytes(StandardCharsets.UTF_8));
            String signingInput = header + "." + payload; // 서명 대상 문자열

            // 5) 서명 생성(HMAC-SHA256) -> Base64URL 인코딩 -> signature
            String sig = b64Url(hmacSha256(signingInput.getBytes(StandardCharsets.UTF_8)));

            // 6) 최종 JWT 반환 (header.payload.signature)
            return signingInput + "." + sig;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to issue JWT", e);
        }
    }


    // 서명 검증
    public boolean isSignatureValid(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) return false;
            String signingInput = parts[0] + "." + parts[1];
            String expected = b64Url(hmacSha256(signingInput.getBytes(StandardCharsets.UTF_8)));
            return MessageDigest.isEqual(
                    expected.getBytes(StandardCharsets.UTF_8),
                    parts[2].getBytes(StandardCharsets.UTF_8)
            );
        } catch (Exception e) {
            return false;
        }
    }

    // HMAC-SHA256 서명 생성 (서버 비밀키 사용)
    private byte[] hmacSha256(byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        byte[] secret = props.jwt().secret().getBytes(StandardCharsets.UTF_8);
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        return mac.doFinal(data);
    }

    // Base64 URL-safe 인코딩 (JWT 표준 방식) 
    private String b64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
