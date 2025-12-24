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
  -d '{"email":"add28482848@kyonggi.ac.kr","code":"172904"}'

[가입 완료]
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  	-H "Content-Type: application/json" \
  	-d '{"email":"add28482848@kyonggi.ac.kr","password":"Abcdef12!","passwordConfirm":"Abcdef12!","nickname":"Anna"}'

[DB 확인]
dmysql -e "select * from users;"
dmysql -e "select * from email_otp;"
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

*/

@SpringBootApplication
@Import(AuthModuleConfig.class)
public class BackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
	}

}

