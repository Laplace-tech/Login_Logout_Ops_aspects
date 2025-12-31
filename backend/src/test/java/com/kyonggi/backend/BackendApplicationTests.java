package com.kyonggi.backend;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * [테스트 DB 초기화]
 * docker exec -i kyonggi-mysql mysql -uroot -proot -e "
 * DROP DATABASE IF EXISTS kyonggi_board_test;
 * CREATE DATABASE kyonggi_board_test CHARACTER SET utf8mb4 COLLATE
 * utf8mb4_0900_ai_ci;
 * GRANT ALL PRIVILEGES ON kyonggi_board_test.* TO 'kyonggi'@'%';
 * FLUSH PRIVILEGES;
 * 
 * [테스트 실행]
 * cd backend
 * ./gradlew test --no-daemon
 * 
 * [에러 로깅 출력]
 * ./gradlew test --no-daemon --info --stacktrace --tests com.kyonggi.backend.BackendApplicationTests

 * 
 */
@ActiveProfiles("test")
@SpringBootTest
class BackendApplicationTests extends AbstractIntegrationTest {
   @Test void contextLoads() {}
}

