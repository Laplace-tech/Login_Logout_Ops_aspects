# Kyonggi Board - Auth Runbook (OTP Signup) + Dev Utilities

MailHog UI: http://localhost:8025/

> 주의
> - backend를 "도커"로 띄울지, "로컬 bootRun"으로 띄울지 **둘 중 하나만** 선택 (8080 충돌 방지)
> - DB 완전 초기화가 필요하면 `down -v` 사용
> - MySQL 포트는 가능하면 `127.0.0.1:3306:3306`으로 묶기(외부 노출 방지)
> - OTP는 정책상 “재발송 쿨다운/일일 제한/실패 횟수 제한”이 있어 테스트 시 이메일을 여러 개로 돌리는 게 편함

---

## 0) 이 파일 저장 위치(추천)

- `~/kyonggi-board/docs/runbook-auth.md` (커밋 추천)

빠르게 파일 만들기:

```bash
cd ~/kyonggi-board
mkdir -p docs
nano docs/runbook-auth.md   # 또는 code docs/runbook-auth.md
```

---

## 1) 공통 유틸 (편의 alias)

아래 함수들을 쉘에 등록해두면 명령이 짧아짐.

- 임시 사용: 터미널에 한 번 붙여넣기
- 영구 사용: `~/.bashrc` 또는 `~/.zshrc`에 추가

### 1-1) dmysql (도커 MySQL 바로 실행)
```bash
dmysql() {
  docker compose -f ~/kyonggi-board/infra/docker-compose.yml exec -T mysql \
    mysql -u kyonggi -pkyonggi kyonggi_board "$@"
}
```

### 1-2) dps (compose 상태)
```bash
dps() {
  docker compose -f ~/kyonggi-board/infra/docker-compose.yml ps
}
```

### 1-3) dlogs (compose 로그)
```bash
dlogs() {
  docker compose -f ~/kyonggi-board/infra/docker-compose.yml logs -f "$@"
}
```

### 1-4) drestart (특정 서비스 재시작)
```bash
drestart() {
  docker compose -f ~/kyonggi-board/infra/docker-compose.yml restart "$@"
}
```

### 1-5) drebuild-backend (도커 backend만 rebuild/restart)
```bash
drebuild-backend() {
  docker compose -f ~/kyonggi-board/infra/docker-compose.yml up -d --build backend
}
```

### 1-6) dsh (컨테이너 쉘 접속)
```bash
dsh() {
  docker exec -it "$1" bash
}
```

---

## 2) 인프라 띄우기 (MySQL + MailHog)

### 2-1) 완전 초기화(볼륨 포함, DB 싹 리셋) ✅ 권장
```bash
cd ~/kyonggi-board/infra
sudo docker compose down -v
sudo docker compose up -d
sudo docker compose ps
```

### 2-2) 그냥 재시작(DB 유지)
```bash
cd ~/kyonggi-board/infra
sudo docker compose down
sudo docker compose up -d
sudo docker compose ps
```

### 2-3) 포트/컨테이너 상태 빠르게 보기
```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### 2-4) Compose 설정 확인(렌더 결과)
```bash
cd ~/kyonggi-board/infra
docker compose config
```

---

## 3) 백엔드 실행 (둘 중 하나만 선택)

### 3-A) 백엔드도 도커로 실행 (compose에 backend 서비스가 있을 때)
```bash
cd ~/kyonggi-board/infra
sudo docker compose up -d --build backend
sudo docker compose ps
sudo docker compose logs -f backend
```

#### 도커 backend만 코드 반영(리빌드)
```bash
cd ~/kyonggi-board/infra
sudo docker compose up -d --build backend
sudo docker compose logs -f backend
```

### 3-B) 백엔드는 로컬 bootRun (추천: 개발 속도 빠름)
```bash
cd ~/kyonggi-board/backend
SPRING_PROFILES_ACTIVE=local ./gradlew bootRun
```

> 도커 backend를 올려둔 상태에서 로컬 bootRun을 또 켜면 8080 충돌/혼란이 생김

---

## 4) 가입 플로우 스모크 테스트 (OTP → verify → complete)

### 4-1) OTP 요청
```bash
curl -i -X POST "http://localhost:8080/auth/signup/otp/request" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr"}'
```
기대: 204

### 4-2) OTP 검증 (MailHog에서 코드 확인 후 입력)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/otp/verify" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr","code":"823223"}'
```
기대: 204

### 4-3) 가입 완료
```bash
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr","password":"Abcdef12!","passwordConfirm":"Abcdef12!","nickname":"Anna"}'
```
기대: 201

---

## 5) 가입 완료(complete) 테스트 케이스 모음

> ⚠️ complete는 OTP 검증 상태가 필요함.  
> 케이스에 따라 “다른 이메일로 OTP request/verify 후” 실행해야 정상적으로 원하는 에러를 볼 수 있음.

### 5-0) 테스트 이메일 세트(편의용)
- ok1@kyonggi.ac.kr
- ok2@kyonggi.ac.kr
- cooldown@kyonggi.ac.kr
- fails@kyonggi.ac.kr
- nootp@kyonggi.ac.kr

### 5-1) passwordConfirm 불일치 → PASSWORD_MISMATCH (서비스)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"ok1@kyonggi.ac.kr","password":"Abcdef12!","passwordConfirm":"Abcdef99!","nickname":"Anna2"}'
```

### 5-2) 약한 비번(짧음) → WEAK_PASSWORD (서비스)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"ok1@kyonggi.ac.kr","password":"1234","passwordConfirm":"1234","nickname":"Anna3"}'
```

### 5-3) 특수문자 없음 → WEAK_PASSWORD (서비스)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"ok1@kyonggi.ac.kr","password":"Abcdef1234","passwordConfirm":"Abcdef1234","nickname":"Anna4"}'
```

### 5-4) 공백 포함 비밀번호 → WEAK_PASSWORD (서비스)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"ok1@kyonggi.ac.kr","password":"Abcdef12! ","passwordConfirm":"Abcdef12! ","nickname":"Anna5"}'
```

### 5-5) 닉네임 공백 포함 → INVALID_NICKNAME (서비스)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"ok1@kyonggi.ac.kr","password":"Abcdef12!","passwordConfirm":"Abcdef12!","nickname":"Anna Lee"}'
```

### 5-6) 닉네임 금지 특수문자 포함 → INVALID_NICKNAME (서비스)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"ok1@kyonggi.ac.kr","password":"Abcdef12!","passwordConfirm":"Abcdef12!","nickname":"Anna!"}'
```

### 5-7) OTP 없이 complete 시도 → OTP_NOT_FOUND (서비스)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"nootp@kyonggi.ac.kr","password":"Abcdef12!","passwordConfirm":"Abcdef12!","nickname":"NoOtp"}'
```

### 5-8) 이메일 도메인 불가 → EMAIL_DOMAIN_NOT_ALLOWED (서비스)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@gmail.com","password":"Abcdef12!","passwordConfirm":"Abcdef12!","nickname":"GmailUser"}'
```

### 5-9) 이메일 중복 → EMAIL_ALREADY_EXISTS (서비스)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr","password":"Abcdef12!","passwordConfirm":"Abcdef12!","nickname":"AnotherNick"}'
```

### 5-10) 닉네임 중복 → NICKNAME_ALREADY_EXISTS (서비스)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"ok2@kyonggi.ac.kr","password":"Abcdef12!","passwordConfirm":"Abcdef12!","nickname":"Anna"}'
```

---

## 6) OTP API 테스트 케이스 모음

### 6-1) OTP 재요청 쿨다운(60초) → OTP_COOLDOWN
```bash
curl -i -X POST "http://localhost:8080/auth/signup/otp/request" \
  -H "Content-Type: application/json" \
  -d '{"email":"cooldown@kyonggi.ac.kr"}'

curl -i -X POST "http://localhost:8080/auth/signup/otp/request" \
  -H "Content-Type: application/json" \
  -d '{"email":"cooldown@kyonggi.ac.kr"}'
```

### 6-2) OTP 검증 실패 5회 → OTP_TOO_MANY_FAILURES
(사전에 `fails@kyonggi.ac.kr`로 otp/request 1회 필요)
```bash
for i in {1..6}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "http://localhost:8080/auth/signup/otp/verify" \
    -H "Content-Type: application/json" \
    -d '{"email":"fails@kyonggi.ac.kr","code":"000000"}'
done
```

### 6-3) OTP 코드 형식 오류(6자리 아님) → VALIDATION_ERROR (컨트롤러)
```bash
curl -i -X POST "http://localhost:8080/auth/signup/otp/verify" \
  -H "Content-Type: application/json" \
  -d '{"email":"add28482848@kyonggi.ac.kr","code":"12"}'
```

---

## 7) DB 확인 명령어 (MySQL)

### 7-1) 테이블/마이그레이션 확인
```bash
dmysql -e "SHOW TABLES;"
dmysql -e "SELECT installed_rank, version, description, success FROM flyway_schema_history ORDER BY installed_rank;"
```

### 7-2) users / email_otp / refresh_tokens 조회
```bash
dmysql -e "SELECT id,email,nickname,role,status,created_at FROM users ORDER BY id DESC LIMIT 20;"
dmysql -e "SELECT email,purpose,expires_at,verified_at,failed_attempts,send_count,last_sent_at,resend_available_at FROM email_otp ORDER BY id DESC LIMIT 20;"
dmysql -e "SELECT id,user_id,remember_me,expires_at,last_used_at,revoked_at,revoke_reason,created_at FROM refresh_tokens ORDER BY id DESC LIMIT 20;"
```

### 7-3) 특정 이메일로 조회
```bash
dmysql -e "SELECT * FROM users WHERE email='add28482848@kyonggi.ac.kr';"
dmysql -e "SELECT * FROM email_otp WHERE email='add28482848@kyonggi.ac.kr';"
```

### 7-4) DB 변수/캐릭터셋 확인(디버깅용)
```bash
dmysql -e "SHOW VARIABLES LIKE 'character_set%';"
dmysql -e "SHOW VARIABLES LIKE 'collation%';"
dmysql -e "SELECT @@time_zone, @@system_time_zone;"
```

### 7-5) 권한/유저 확인(디버깅용)
```bash
dmysql -e "SELECT user, host FROM mysql.user;"
dmysql -e "SHOW GRANTS FOR 'kyonggi'@'%';"
```

### 7-6) 테이블 사이즈 확인(대충)
```bash
dmysql -e "
SELECT table_name,
       ROUND((data_length+index_length)/1024/1024, 2) AS mb
FROM information_schema.tables
WHERE table_schema='kyonggi_board'
ORDER BY (data_length+index_length) DESC;"
```

### 7-7) 빠른 정리(개발용) - 주의해서 사용
```bash
# 모든 OTP 삭제
dmysql -e "DELETE FROM email_otp;"

# (주의) 유저 삭제는 FK/정책 확인 후
# dmysql -e "DELETE FROM users WHERE email='...';"
```

---

## 8) Docker 유용한 명령어

### 8-1) 컨테이너 상태 / 포트 확인
```bash
cd ~/kyonggi-board/infra
docker compose ps
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### 8-2) 로그 보기
```bash
cd ~/kyonggi-board/infra
docker compose logs -f mysql
docker compose logs -f mailhog
docker compose logs -f backend
```

### 8-3) 컨테이너 쉘/DB 접속
```bash
docker exec -it kyonggi-mysql bash
docker exec -it kyonggi-mysql mysql -ukyonggi -pkyonggi kyonggi_board
```

### 8-4) 특정 서비스만 재시작
```bash
cd ~/kyonggi-board/infra
docker compose restart mysql
docker compose restart mailhog
docker compose restart backend
```

### 8-5) 네트워크/볼륨 확인
```bash
docker network ls
docker volume ls
```

### 8-6) 완전 초기화(볼륨 포함) - 제일 강력함
```bash
cd ~/kyonggi-board/infra
sudo docker compose down -v
sudo docker compose up -d
```

---

## 9) 트러블슈팅

### 9-1) 8080 포트 충돌
- 도커 backend + 로컬 bootRun을 동시에 켰을 가능성 높음
- 둘 중 하나만 실행

### 9-2) Flyway 적용이 안 된 것 같음
```bash
dmysql -e "SELECT * FROM flyway_schema_history;"
dmysql -e "SHOW TABLES;"
```

### 9-3) “요청 값이 올바르지 않습니다.”만 나와서 원인 파악이 어려움
- 정책: 클라이언트 응답은 단순 메시지 유지
- 필요하면 서버 로그(debug)로 validation 원인을 남기는 방식 권장

---

## 10) 보관/운영 팁
- 이 문서는 `docs/runbook-auth.md`로 커밋해두고,
  PR 템플릿이나 README에 “Runbook 링크”만 걸어두면 팀원들이 잘 따라옴
