package com.kyonggi.backend;

import java.time.Duration;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MySQLContainer;

/**
 * 통합테스트 공통 베이스 클래스 (모든 통합 테스트가 상속하는 뼈대)
 *
 * ✅ 이 클래스 1개로 해결하려는 문제
 * - 통합테스트는 "진짜 DB/메일" 같은 외부자원이 필요함
 * - 로컬 환경(MySQL 설치/메일서버 등)에 의존하면 사람마다 깨짐
 * - 그래서 테스트 실행 시 컨테이너로 외부자원을 자동으로 띄우고,
 * Spring 설정을 그 컨테이너로 강제 연결한다.
 *
 * ✅ 보장되는 것
 * 1) 컨테이너가 반드시 켜진다 (상속/애너테이션 꼬임 방지)
 * 2) 스프링이 반드시 컨테이너 DB/메일로 붙는다 (yml 무시하고 강제 주입)
 */
@SpringBootTest // ✅ "스프링 컨텍스트"를 실제로 띄운다. (단위테스트 X, 통합테스트 O)
@ActiveProfiles("test") // ✅ application-test.yml 프로필을 활성화한다.
public abstract class AbstractIntegrationTest {

    /**
     * ✅ MySQL 컨테이너
     *
     * - static: 테스트 클래스가 10개여도 JVM 기준으로 "1번만" 생성/실행시키려는 의도
     * - mysql:8.0.36: 테스트 DB 엔진 버전 고정 (버전 바뀌면 미묘한 차이로 깨질 수 있어서)
     * - withDatabaseName/Username/Password: 컨테이너 내부 DB 계정/스키마 세팅
     * - startupAttempts/startupTimeout: 느린 환경(Wsl/CI)에서도 안정성 올리는 보험
     *
     * ✅ 핵심 포인트:
     * - "테스트는 로컬 MySQL을 절대 안 쓴다."
     * - 항상 이 컨테이너 DB로만 붙는다.
     */
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.0.36")
            .withDatabaseName("kyonggi_board_test")
            .withUsername("kyonggi")
            .withPassword("kyonggi")
            .withStartupAttempts(3)
            .withStartupTimeout(Duration.ofMinutes(2));

    /**
     * ✅ MailHog 컨테이너
     *
     * - OTP 메일 통합테스트를 "진짜로" 하려면 SMTP 서버가 필요함
     * - MailHog는 테스트용 SMTP + 웹 UI(API)를 제공
     *
     * - 1025: SMTP 포트 (스프링이 메일 발송할 때 붙는 포트)
     * - 8025: HTTP 포트 (테스트가 메일 내용을 조회/파싱할 때 쓰는 포트)
     */
    // ✅ MailHog: “컨테이너 시작”이 아니라 “HTTP API가 200 줄 때까지” 기다리게
    static final GenericContainer<?> MAILHOG = new GenericContainer<>("mailhog/mailhog:v1.0.1")
            .withExposedPorts(1025, 8025)
            .waitingFor(
                    org.testcontainers.containers.wait.strategy.Wait
                            .forHttp("/api/v2/messages")
                            .forPort(8025)
                            .forStatusCode(200));

    /**
     * ✅ static 블록에서 start()를 직접 호출하는 이유 (중요)
     *
     * - Testcontainers는 보통 @Testcontainers + @Container로 자동 실행시킬 수 있음
     * - 하지만 "상속 구조 + 스프링 컨텍스트"가 섞이면
     * 가끔 컨테이너가 안 뜨거나 늦게 떠서 datasource 연결이 터지는 꼬임이 생김
     *
     * ✅ 그래서 그냥 여기서 강제로 start() 호출해서:
     * - "스프링 컨텍스트가 뜨기 전에"
     * - DB/메일 컨테이너가 100% 살아있음을 보장한다.
     */
    static {
        try {
            MYSQL.start();
            MAILHOG.start();

            System.setProperty(
                    "test.mailhog.base-url",
                    "http://" + getMailhogHost() + ":" + getMailhogHttpPort());

            System.out.println("[TEST] Containers started");
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("❌ Testcontainer init failed", e);
        }
    }

    /**
     * 스프링 설정을 "동적으로" 덮어씌우는 함수: 테스트를 언제나 컨테이너 DB로 붙게하고 로컬 환경과 무관함
     * - @DynamicPropertySource 는 스프링이 ApplicationContext를 만들기 전에 실행된다.
     * - application-test.yml에 뭐가 적혀있든 상관없이 "datasource"와 "flyway"설정을 컨테이너 DB로 강제한다.
     */
    @DynamicPropertySource
    static void overrideProps(DynamicPropertyRegistry r) {

        // --- datasource ---
        r.add("spring.datasource.url", MYSQL::getJdbcUrl);
        r.add("spring.datasource.username", MYSQL::getUsername);
        r.add("spring.datasource.password", MYSQL::getPassword);
        r.add("spring.datasource.driver-class-name", () -> "com.mysql.cj.jdbc.Driver");

        // --- flyway ---
        r.add("spring.flyway.url", MYSQL::getJdbcUrl);
        r.add("spring.flyway.user", MYSQL::getUsername);
        r.add("spring.flyway.password", MYSQL::getPassword);

        // --- hikari ---
        r.add("spring.datasource.hikari.connection-timeout", () -> "30000");
        r.add("spring.datasource.hikari.initialization-fail-timeout", () -> "-1");

        // --- mail ---
        r.add("spring.mail.host", AbstractIntegrationTest::getMailhogHost);
        r.add("spring.mail.port", AbstractIntegrationTest::getMailhogSmtpPort);

        r.add("spring.mail.properties.mail.smtp.auth", () -> "false");
        r.add("spring.mail.properties.mail.smtp.starttls.enable", () -> "false");
        r.add("spring.mail.properties.mail.smtp.starttls.required", () -> "false");

        // ✅ (중요) MailhogSupport가 쓸 base-url도 Spring 환경에 제공
        r.add("test.mailhog.base-url",
                () -> "http://" + getMailhogHost() + ":" + getMailhogHttpPort());
    }

    public static String getMailhogHost() {
        return MAILHOG.getHost();
    }

    public static int getMailhogSmtpPort() {
        return MAILHOG.getMappedPort(1025);
    }

    public static int getMailhogHttpPort() {
        return MAILHOG.getMappedPort(8025);
    }
}
