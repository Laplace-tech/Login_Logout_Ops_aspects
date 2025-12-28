package com.kyonggi.backend.security;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.kyonggi.backend.auth.config.AuthProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/**
 * Access Token(JWT) 발급/검증 서비스
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
 * 발급: issueAccessToken(userId, role) - JWT 생성 (header/payload/signature를 jjwt가 알아서 만들어줌)
 * 검증: verifyAccessToken(token) - 서명/만료/issuer 검증 후 AuthPrincipal로 복원
 */
@Service
public class JwtService {

    private static final int MIN_SECRET_BYTES = 32;
    private static final String ROLE_CLAIM = "role"; 

    private final AuthProperties.Jwt jwtProps;
    private final Clock clock;
    private final SecretKey key;
    private final JwtParser jwtParser;

    public JwtService(AuthProperties props, Clock clock) {
        this.jwtProps = props.jwt(); // 설정값 한 번에 가져오기
        this.clock = clock;

        /**
         * [AuthProperties.Jwt.secret() -> secretBytes[] -> key -> jwtParser]
         * 
         * 1. AuthProperties.Jwt에서 가져온 설정 값을 secretBytes로 바꿈 (32Byte 이상)
         * 2. 그 바이트 배열로 secretKey를 만듦: Keys.hmacShaKeyFor(secretBytes)
         * 3. 이 키로 JwtParser를 하나 만들어놓고, issuer도 여기서 강제
         *     - 나중에 parseClaimsJws(token)으로 
         *       * 서명 검증
         *       * 만료(exp) 체크
         *       * issuer가 맞는지 확인
         */
        byte[] secretBytes = jwtProps.secret().getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException("JWT secret must be at least " + MIN_SECRET_BYTES + " bytes for HS256");
        }

        // secretBytes로 HMAC용 SecretKey 생성
        this.key = Keys.hmacShaKeyFor(secretBytes);
 
        // Parser 빌딩: 향후 verifyAccessToken()에서 지금 설정된 발행자(issuer)와 key로 검증
        this.jwtParser = Jwts.parserBuilder()
                .requireIssuer(jwtProps.issuer()) //
                .setSigningKey(this.key)
                .build();
    }

    // "userId, role" 기반으로 Access Token을 만들어 발행
    public String issueAccessToken(Long userId, String role) {
        if(userId == null) throw new IllegalArgumentException("userId must not be null");
        if(role == null || role.isBlank()) throw new  IllegalArgumentException("role must not be blank");

        Instant now = clock.instant();
        Instant exp = now.plusSeconds(jwtProps.accessTtlSeconds());
        
        return Jwts.builder()
                .setIssuer(jwtProps.issuer())           // iss
                .setSubject(String.valueOf(userId))     // sub
                .claim(ROLE_CLAIM, role)                // role
                .setIssuedAt(Date.from(now))            // iat
                .setExpiration(Date.from(exp))          // exp
                .signWith(key, SignatureAlgorithm.HS256) // header.alg / signature 생성
                .compact(); // header.payload.signature 문자열로 조합                
    }

    /**
     * Access Token 검증 후, AuthPrincipal 리턴
     * 
     * 실패하면 InvalidJwtException을 던진다
     * - Filter에서 잡아서 401 JSON으로 변환
     */
    public AuthPrincipal verifyAccessToken(String token) {
        try {
            if (token == null || token.isBlank()) 
                throw new JwtException("token is null or blank");
            
            /** 
             * jwtParser.parseClaimsJws(token): 하나라도 깨지면 JwtException 발생!
             * 
             * - 토큰 포맷이 "header.payload.signature"인지 확인
             * - header, payload를 Base64URL로 디코딩
             * - signature가 우리 서버 키로 다시 계산했을 때 동일한지 서명 검증
             * - exp가 현재 시간보다 과거면 → 만료 예외
             * - iss가 설정된 issuer와 다른 경우 → 예외
             */
            Jws<Claims> jws = jwtParser.parseClaimsJws(token);
            Claims claims = jws.getBody();

            // 클레임에서 userId, role 꺼내기
            Long userId = parseUserId(claims);
            String role = claims.get(ROLE_CLAIM, String.class);

            if (role == null || role.isBlank()) 
                throw new JwtException("role claim missing");

            return new AuthPrincipal(userId, role);
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidJwtException("Invalid JWT", e); // 여기서는 HTTP 모른다. 그냥 "JWT가 잘못됐다"는 도메인 예외만 던짐.
        }
    }

    // subject:userId -> Long userId 파싱
    private static Long parseUserId(Claims claims) {
        String sub = claims.getSubject();
        if(sub == null || sub.isBlank()) 
            throw new JwtException("subject (userId) is missing");
        
        try {
            return Long.valueOf(sub);
        } catch (NumberFormatException ex) {
            throw new JwtException("subject is not a valid Long: " + sub, ex);
        }
    }
    
    // HMAC-SHA256 서명 생성 (서버 비밀키 사용)
    private byte[] hmacSha256(byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(this.key); // 생성자에서 만든 SecretKey 재사용
        return mac.doFinal(data);
    }

    // Base64 URL-safe 인코딩 (JWT 표준) 
    private String b64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * "HTTP를 모르는 도메인 예외"
     * - Filter/Conroller에서 잡아서 ApiException 또는 401로 매핑하여 처리
     */
    public static class InvalidJwtException extends RuntimeException {
        public InvalidJwtException(String message, Throwable cause) {
            super(message, cause);
        }
    }

}

    // /**
    //  * =================
    //  * Access Token 발급
    //  * =================
    //  * 
    //  * 입력: userId, role
    //  * 출력: JWT 문자열(header.payload.signature)
    //  * 
    //  * 발급 흐름
    //  * - header JSON 생성 ("alg": "HS256", "typ": "JWT")
    //  * - payload JSON 생성 (iat/exp 포함)
    //  * - Base64URL 인코딩 -> "header.payload" 서명 (HMAC-SHA256)
    //  * - signature까지 붙여서 반환
    //  */
    // public String issueAccessToken(Long userId, String role) {
    //     try {
    //         // 1) JWT header: 어떤 알고리즘으로 서명했는지 + 타입 {"alg": "HS256", "typ": "JWT"}
    //         String headerJson = om.writeValueAsString(Map.of("alg", "HS256", "typ", "JWT"));
            
    //         // 2) issued_at/expire: epoch seconds(초 단위)
    //         long now = Instant.now(clock).getEpochSecond();
    //         long exp = now + jwtProps.accessTtlSeconds();

    //         /**
    //          * 3) JWT payload(클레임): "이 토큰은 누구 것인지 판단"
    //          * - iss (issue): 발급자(우리 서비스)
    //          * - sub: 유저 식별자(여기선 userId)
    //          * - role: 권한(인가에 사용)
    //          * - iat(issue_at)/exp(expire): 발급/만료
    //          */
    //         String payloadJson = om.writeValueAsString(Map.of(
    //                 "iss", jwtProps.issuer(),
    //                 "sub", String.valueOf(userId),
    //                 "role", role,
    //                 "iat", now,
    //                 "exp", exp
    //         ));

    //         // 4) header/payload를 Base64URL 인코딩
    //         String header = b64Url(headerJson.getBytes(StandardCharsets.UTF_8));
    //         String payload = b64Url(payloadJson.getBytes(StandardCharsets.UTF_8));
    //         String signingInput = header + "." + payload; // 서명 대상 문자열

    //         // 5) 서명 생성(HMAC-SHA256) -> Base64URL 인코딩 -> signature
    //         String sig = b64Url(hmacSha256(signingInput.getBytes(StandardCharsets.UTF_8)));

    //         // 6) 최종 JWT 반환 (header.payload.signature)
    //         return signingInput + "." + sig;
    //     } catch (Exception e) {
    //         throw new IllegalStateException("Failed to issue JWT", e);
    //     }
    // }