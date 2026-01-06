package com.kyonggi.backend;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import com.kyonggi.backend.support.TestClockConfig;

import lombok.extern.slf4j.Slf4j;

/**
 * [테스트 실행]:
 * - cd backend
 * - ./gradlew test --rerun-tasks --info --no-daemon
 *
 * [특정 테스트만 실행]:
 * - ./gradlew test --no-daemon --tests com.kyonggi.backend.BackendApplicationTests
 */


/**
 * AbstractIntegrationTest: 
 * - 테스트 실행 시, 로컬 환경(내 PC의 MySQL/SMTP)과 완전히 독립된 '테스트 전용 환경'을 JVM안에서 구성한다.
 * 
 * 1) DB: Testcontainers MySQL (항상 같은 버전/깨끗한 DB)
 * 2) 메일: MailHog 컨테이너 (SMTP + 조회용 HTTP API)
 * 3) 시간: 테스트 전용 Clock (시간을 고정/이동 가능하게)
 * 
 * [테스트 실행]:
 * - cd backend
 * - ./gradlew test --rerun-tasks --info --no-daemon
 *
 * [특정 테스트만 실행]:
 * - ./gradlew test --no-daemon --tests com.kyonggi.backend.BackendApplicationTests
 */

@Slf4j
@SpringBootTest       // 실제 스프링 애플리케이션을 통째로 띄운다.
@AutoConfigureMockMvc // 실제 톰캣을 띄우지 않고도 MVC 계층을 요청/응답으로 테스트 할 수 있다.
@ActiveProfiles("test") // application-test.yml / test 프로필 빈 구성을 활성화한다.
@Import(TestClockConfig.class) // 테스트에서만 쓰는 Clock Bean을 주입한다.
public abstract class AbstractIntegrationTest {

    private static final String MYSQL_IMAGE = "mysql:8.0.36";
    private static final String MYSQL_DB = "kyonggi_board_test";
    private static final String MYSQL_USER = "kyonggi";
    private static final String MYSQL_PASSWORD = "kyonggi";

    /**
     * - SMTP 1025: 스프링(JavaMailSender)가 "메일을 보내는 대상"
     * - HTTP 8025: 테스트 코드가 "메일을 읽어서 OTP를 추출"할 때 쓰는 API
     */
    private static final String MAILHOG_IMAGE = "mailhog/mailhog:v1.0.1";
    private static final int MAILHOG_SMTP_PORT = 1025;
    private static final int MAILHOG_HTTP_PORT = 8025;

    @BeforeEach
    void resetTestClock() {
        TestClockConfig.reset(); // 매 테스트 메서드마다 Clock을 초기화
    }

    /**
     * [Testcontainers: MySQLContainer]
     * 
     * "컨테이너 포트는 랜덤 매핑"
     * - 컨테이너 내부 3306이 항상 로컬 3306으로 매핑되는 게 아님.
     * - 그래서 jdbcUrl을 하드코딩하면 안 되고 getJdbcUrl()로 받아야 한다.
     */
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(MYSQL_IMAGE)
            .withDatabaseName(MYSQL_DB)
            .withUsername(MYSQL_USER)
            .withPassword(MYSQL_PASSWORD)
            .withStartupAttempts(3)
            .withStartupTimeout(Duration.ofMinutes(2));

    /**
     * [GenericContainer: MailHog]
     *
     * waitingFor(Wait.forHttp...):
     * - 컨테이너 "프로세스"가 떴다고 해서 내부 서비스(HTTP API)가 즉시 준비되는 건 아님.
     * - 준비되기 전에 테스트가 API 호출하면 404/connection refused로 간헐 실패.
     * - 그래서 "HTTP 200 나올 때까지 기다림"을 걸어 안정화.
     */
    static final GenericContainer<?> MAILHOG = new GenericContainer<>(MAILHOG_IMAGE)
            .withExposedPorts(MAILHOG_SMTP_PORT, MAILHOG_HTTP_PORT)
            .waitingFor(
                    Wait.forHttp("/api/v2/messages")
                            .forPort(MAILHOG_HTTP_PORT)
                            .forStatusCode(200));

    /**
     * [static 초기화 블록에서 컨테이너를 먼저 부팅]
     * 
     * - @SpringBootTest는 컨텍스트 만들면서 DataSource 초기화를 시도하는데
     *    그 순간 DB가 아직 준비 안 되어 있으면 ApplicationContext가 아예 실패한다.
     * 
     * - Testcontainers 정석은 @Testcontainers + @Container지만,
     *    "상속 구조 + 스프링 컨텍스트" 조합에서 컨테이너 스타트 타이밍이 꼬여서
     *    datasource 연결이 먼저 시도되는 케이스가 가끔 생긴다.
     * 
     * - 그래서, 스프링부트가 뜨기 전에 컨테이너부터 확정적으로 켠다.
     *    그 후, 스프링을 키고 컨텍스트를 만들면서 datasource로 안전하게 DB와 연결
     */
    static {
        startContainersOnce();
    }

    @DynamicPropertySource
    static void overrideProps(DynamicPropertyRegistry r) {

        // datasource 연결을 컨테이너 DB로 강제
        r.add("spring.datasource.url", MYSQL::getJdbcUrl);
        r.add("spring.datasource.username", MYSQL::getUsername);
        r.add("spring.datasource.password", MYSQL::getPassword);
        r.add("spring.datasource.driver-class-name", () -> "com.mysql.cj.jdbc.Driver");

        // flyway: 마이그레이션도 같은 DB로 강제
        r.add("spring.flyway.url", MYSQL::getJdbcUrl);
        r.add("spring.flyway.user", MYSQL::getUsername);
        r.add("spring.flyway.password", MYSQL::getPassword);

        // hikari: 컨테이너 환경에서 연결 지연이 있어도 덜 터지게 보험
        r.add("spring.datasource.hikari.connection-timeout", () -> "30000");
        r.add("spring.datasource.hikari.initialization-fail-timeout", () -> "-1");

        // mail: 컨테이너 MailHog로 강제
        r.add("spring.mail.host", AbstractIntegrationTest::getMailhogHost);
        r.add("spring.mail.port", AbstractIntegrationTest::getMailhogSmtpPort);

        // MailHog는 auth/tls 필요 없음
        r.add("spring.mail.properties.mail.smtp.auth", () -> "false");
        r.add("spring.mail.properties.mail.smtp.starttls.enable", () -> "false");
        r.add("spring.mail.properties.mail.smtp.starttls.required", () -> "false");

        // 테스트 코드(MailhogSupport)가 HTTP API를 때릴 base-url도 함께 제공
        r.add("test.mailhog.base-url", AbstractIntegrationTest::mailhogBaseUrl);
    }

    // 컨테이너 스타트
    private static void startContainersOnce() {
        try {
            MYSQL.start();
            MAILHOG.start();

            String baseUrl = mailhogBaseUrl();
            System.setProperty("test.mailhog.base-url", baseUrl);

            log.info("===================================================================");
            log.info("[TEST] Containers started");
            log.info("[TEST] MySQL jdbcUrl={}", MYSQL.getJdbcUrl());
            log.info("[TEST] MailHog smtp={} http={} baseUrl={}", getMailhogSmtpPort(), getMailhogHttpPort(), baseUrl);
            log.info("==================================================================="); 

        } catch (Exception e) {
            log.error("❌ Testcontainer init failed", e);
            throw new IllegalStateException("❌ Testcontainer init failed", e);
        }
    }

    public static String getMailhogHost() {
        return MAILHOG.getHost();
    }

    public static int getMailhogSmtpPort() {
        return MAILHOG.getMappedPort(MAILHOG_SMTP_PORT);
    }

    public static int getMailhogHttpPort() {
        return MAILHOG.getMappedPort(MAILHOG_HTTP_PORT);
    }

    private static String mailhogBaseUrl() {
        return "http://" + getMailhogHost() + ":" + getMailhogHttpPort();
    }
}