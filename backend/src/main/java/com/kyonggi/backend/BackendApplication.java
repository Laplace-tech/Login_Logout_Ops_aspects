package com.kyonggi.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

import com.kyonggi.backend.auth.config.AuthModuleConfig;

/*
MailHog: http://localhost:8025/

[초기화]
cd ~/kyonggi-board/infra
sudo docker compose down -v 
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs -f backend

[포트 확인]
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

[rebuild]
sudo docker compose up -d --build backend

[메일 발송]
curl -i -X POST "http://localhost:8080/auth/signup/otp/request" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr"}' 

[OTP 검증]
curl -i -X POST "http://localhost:8080/auth/signup/otp/verify" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr","code":"830145"}'

[가입 완료]
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  	-H "Content-Type: application/json" \
  	-d '{"email":"add28482848@kyonggi.ac.kr","password":"28482848a!","passwordConfirm":"28482848a!","nickname":"Anna"}'

[로그인] - 리프레쉬 토큰 /tmp/kyonggi_cookie.txt 에 저장
curl -i -X POST "http://localhost:8080/auth/login" \
  -H "Content-Type: application/json" \
  -c /tmp/kyonggi_cookie.txt \
  -d '{"email":"add28482848@kyonggi.ac.kr","password":"28482848a!","rememberMe":false}'

[me 호출]
curl -i -X GET "http://localhost:8080/auth/me" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJreW9uZ2dpLWJvYXJkIiwic3ViIjoiMSIsInJvbGUiOiJVU0VSIiwiaWF0IjoxNzY2OTExODg0LCJleHAiOjE3NjY5MTI3ODR9.firSiZZ6HvNiDFLUIAAVtKeIaOrUf9L8zuVDNXzBQwE"

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
*/



/**
 * ApplicationContext (스프링 컨테이너): 
 * - 애플리케이션을 구성하는 @Bean(컴포넌트)들의 의존성 그래프를 만들고, 생명주기를 관리하는 런타임
 * - @SpringBootApplication이 붙은 메인 클래스 패기지를 기준으로 하위 패키지를 스캔 (컴포넌트 스캔 / 구성 클래스 파싱)
 * - @Component/@Service/@Repository/@Controller 등을 스캔해서 컨텍스트에 자동 등록
 * 
 */
@SpringBootApplication
@Import(AuthModuleConfig.class)
public class BackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
	}

}

