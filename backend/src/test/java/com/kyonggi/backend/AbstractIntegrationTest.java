package com.kyonggi.backend;

import java.time.Duration;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;

/**
 * ✅ 통합테스트 공통 베이스
 * - 컨테이너를 "어노테이션에 맡기지 말고" 여기서 강제로 start() 해서
 *   상속/확장 꼬임으로 컨테이너가 안 뜨는 문제를 원천 차단한다.
 */
@SpringBootTest
@ActiveProfiles("test")
public abstract class AbstractIntegrationTest {

    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.0.36")
            .withDatabaseName("kyonggi_board_test")
            .withUsername("kyonggi")
            .withPassword("kyonggi")
            .withStartupAttempts(3)
            .withStartupTimeout(Duration.ofMinutes(2));

    // ✅ 핵심: 무조건 컨테이너를 먼저 띄운다 (상속/어노테이션 문제 무시)
    static {
        MYSQL.start();
        System.out.println("[TEST] MySQLContainer started. jdbcUrl=" + MYSQL.getJdbcUrl());
    }

    @DynamicPropertySource
    static void overrideProps(DynamicPropertyRegistry r) {
        // --- JPA datasource ---
        r.add("spring.datasource.url", MYSQL::getJdbcUrl);
        r.add("spring.datasource.username", MYSQL::getUsername);
        r.add("spring.datasource.password", MYSQL::getPassword);
        r.add("spring.datasource.driver-class-name", () -> "com.mysql.cj.jdbc.Driver");

        // --- Flyway도 같은 DB로 붙게 강제(보험) ---
        r.add("spring.flyway.url", MYSQL::getJdbcUrl);
        r.add("spring.flyway.user", MYSQL::getUsername);
        r.add("spring.flyway.password", MYSQL::getPassword);

        // --- Hikari: 3초는 너무 짧음. 테스트에선 넉넉히 ---
        r.add("spring.datasource.hikari.connection-timeout", () -> "30000"); // 30s
        r.add("spring.datasource.hikari.initialization-fail-timeout", () -> "-1");
    }
}
