package com.kyonggi.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

import com.kyonggi.backend.auth.config.AuthModuleConfig;

/*
MailHog: http://localhost:8025/

[초기화]
cd ~/kyonggi-board/infra
sudo docker compose down
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs -f backend

[rebuild]
sudo docker compose up -d --build backend

[백엔드 실행]
cd ~/kyonggi-board/backend
SPRING_PROFILES_ACTIVE=local ./gradlew bootRun

[메일 발송]
curl -i -X POST "http://localhost:8080/auth/signup/otp/request" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr"}' 

[OTP 검증]
curl -i -X POST "http://localhost:8080/auth/signup/otp/verify" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr","code":"823223"}'

[가입 완료]
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  	-H "Content-Type: application/json" \
  	-d '{"email":"add28482848@kyonggi.ac.kr","password":"Abcdef12!","passwordConfirm":"Abcdef12!","nickname":"Anna"}'

[DB 확인: users]
dmysql -e "select * from users"

[DB 확인: email_otp]
dmysql -e "select * from email_otp"

*/

@SpringBootApplication
@Import(AuthModuleConfig.class)
public class BackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
	}

}
