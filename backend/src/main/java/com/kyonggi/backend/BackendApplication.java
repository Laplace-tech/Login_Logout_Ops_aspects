package com.kyonggi.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Import;

import com.kyonggi.backend.auth.config.AuthModuleConfig;

/*
MailHog: http://localhost:8025/

[도커 리셋/기동]
cd ~/kyonggi-board/infra
sudo docker compose down -v
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs -f backend

[포트 및 프로세스 확인]
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
sudo lsof -i :8080
sudo lsof -i

[rebuild]
sudo docker compose up -d --build backend

# OTP 요청 204
curl -i -X POST "http://localhost:8080/auth/signup/otp/request" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr"}'

# OTP 검증 204
curl -i -X POST "http://localhost:8080/auth/signup/otp/verify" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr","code":"717370"}'

# 가입 완료 201
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr","password":"28482848a!","passwordConfirm":"28482848a!","nickname":"Anna"}'

# 로그인 (쿠키 파일에 저장) 200
curl -i -X POST "http://localhost:8080/auth/login" \
  -H "Content-Type: application/json" \
  -c /tmp/kyonggi_cookie.txt \
  -d '{"email":"add28482848@kyonggi.ac.kr","password":"28482848a!","rememberMe":false}'

# 쿠키 파일 내용 확인(저장된 refresh 확인)
cat /tmp/kyonggi_cookie.txt

# /auth/me (accessToken 넣어서)
curl -i -X GET "http://localhost:8080/auth/me" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJreW9uZ2dpLWJvYXJkIiwic3ViIjoiMyIsInJvbGUiOiJVU0VSIiwiaWF0IjoxNzY3MDE0MTU0LCJleHAiOjE3NjcwMTUwNTR9.vosFR395rEGyjnpLoFAYYDCrDe3irDIus7DHz8lm2sk"

# refresh (기존 쿠키 보내고, 새 쿠키로 덮어쓰기)
curl -i -X POST "http://localhost:8080/auth/refresh" \
  -b /tmp/kyonggi_cookie.txt \
  -c /tmp/kyonggi_cookie_new.txt

# 새 쿠키 확인
cat /tmp/kyonggi_cookie_new.txt

# 로그아웃 (쿠키 보내고, 서버가 만료 Set-Cookie 내려줌 + 쿠키파일 갱신)
curl -i -X POST "http://localhost:8080/auth/logout" \
  -b /tmp/kyonggi_cookie_new.txt \
  -c /tmp/kyonggi_cookie_after_logout.txt

# 로그아웃 후 쿠키 파일 확인(대부분 만료/빈값으로 바뀜)
cat /tmp/kyonggi_cookie_after_logout.txt



[DB 확인]
dmysql -e "select * from users;"
dmysql -e "select * from email_otp;"
dmysql -e "select * from refresh_tokens;"
dmysql -e "show databases;"
dmysql -e "show tables"

[table: email_otp]
datetime1: expires_at
datetime2: verified_at
datetime3: last_sent_at
datetime4: resend_available_at
date: send_count_date
datetime5: created_at
datetime6: updated_at

./gradlew clean test --stacktrace
grep -Rni --include="*.java" "AuthProperties" .
rm /tmp/*.txt

*/



/**
 * 설정(Configurations) 로딩/바인딩 흐름 (Docker Compose + Spring Boot)
 *
 * 설정 값 주입 흐름:  
 * 
 *    .env -> docker-compose.yml -> application.yml -> @ConfigurationProperties
 * 
 *   (A) docker compose가 .env로 "compose 변수"를 채운다 (infra/.env)
 *   (B) compose가 backend 컨테이너에 "OS 환경변수"를 주입한다 (infra/docker-compose.yml:environment)
 *   (C) Spring Boot가 그 환경변수를 Property Source로 읽어서 application.yml의 ${...}를 해석하고
 *   (D) 최종 프로퍼티를 @ConfigurationProperties(AuthProperties/OtpProperties)로 타입 안전하게 바인딩한다.
 *
 * ------------------------------------------------------------------------------------
 * 1) infra/.env  (Compose variable file) 
 * ------------------------------------------------------------------------------------
 * - 대상: Docker Compose 자체(컨테이너가 아니라 compose CLI)가 읽는다.
 * - 용도: docker-compose.yml 안의 ${VAR} 같은 "치환(Interpolation)"에만 쓰인다.
 * - 핵심: .env에 적힌 값이 자동으로 컨테이너 env로 들어가는 게 아니다.
 *         반드시 docker-compose.yml의 environment: 에서 ${VAR}로 참조해서 컨테이너에 전달해야 한다.
 *
 * ------------------------------------------------------------------------------------
 * 2) infra/docker-compose.yml  (Container runtime spec)
 * ------------------------------------------------------------------------------------
 * - 대상: 컨테이너 런타임 설정(서비스 생성/네트워크/볼륨/헬스체크/포트 바인딩 등)을 정의한다.
 * - 역할(중요):
 *   2-1) backend 컨테이너에 OS 환경변수 주입
 *        environment:
 *          SPRING_PROFILES_ACTIVE=local
 *          SPRING_DATASOURCE_URL=jdbc:mysql://mysql:3306/...
 *          APP_AUTH_JWT_SECRET=${APP_AUTH_JWT_SECRET:?required}
 *          ...
 *
 *        여기서 ":?required" 패턴은 compose 단계에서 "필수값 누락"을 즉시 실패시켜
 *        기본값으로 조용히 기동되는 운영사고를 방지한다.
 *
 *   2-2) 컨테이너 내부 네트워크 관점
 *        backend → mysql 접근은 localhost가 아니라 서비스명(mysql:3306)을 쓴다.
 *        (localhost는 "backend 컨테이너 자기 자신"을 의미하므로 DB 컨테이너가 아니다.)
 *
 * ------------------------------------------------------------------------------------
 * 3) backend application.yml  (Spring Boot config model)
 * ------------------------------------------------------------------------------------
 * - 대상: Spring Boot가 부팅 시 읽는 설정 모델.
 * - ${ENV:default} 구문:
 *   - 우선 OS 환경변수(컨테이너 env)에서 ENV를 찾고
 *   - 없으면 default를 사용한다.
 *
 * - 즉, compose에서 주입한 값이 있으면 application.yml의 기본값은 사실상 fallback 용도다.
 *
 * ------------------------------------------------------------------------------------
 * 4) Spring Boot Property Resolution + Binding
 * ------------------------------------------------------------------------------------
 * - Spring은 "Property Sources(설정 원천)"를 우선순위로 합쳐 최종 프로퍼티 맵을 만든다.
 *   일반적으로 OS 환경변수 > application.yml > 기타(기본값/프로필/args...)
 *
 * - 그 다음:
 *   @ConfigurationProperties(prefix="app.auth") 같은 클래스에 값을 바인딩한다.
 *   @Validated가 붙어있으면 바인딩 직후 Bean Validation을 수행하고
 *   조건 위반 시 애플리케이션은 "조용히"가 아니라 "부팅 실패"로 즉시 터진다. (Fail-fast)
 *
 * ------------------------------------------------------------------------------------
 * 5) Startup logs에서 확인 가능한 포인트(실전 체크)
 * ------------------------------------------------------------------------------------
 * - 프로필 적용 여부:
 *     "The following 1 profile is active: \"local\""
 * - DB 연결 여부:
 *     HikariPool started / Added connection
 * - Flyway 적용 여부:
 *     Successfully applied ... migration
 * 
 * - (주의) "Using generated security password" 경고: 기본 유저 자동생성
 *     UserDetailsService 자동설정이 살아있다는 뜻(=기본 인메모리 유저 생성).
 *     JWT 방식이면 기능적으로 치명적이진 않지만, 의도치 않은 보안 자동설정 신호라 정리 대상.
 * 
 * -> @SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})로 AutoConfig 끄기  
 */
@Import(AuthModuleConfig.class)
@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class BackendApplication {
    public static void main(String[] args) {
        SpringApplication.run(BackendApplication.class, args);
    }
}
