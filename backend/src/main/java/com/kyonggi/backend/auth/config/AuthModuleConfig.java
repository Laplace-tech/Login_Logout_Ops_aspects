package com.kyonggi.backend.auth.config;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.ZoneId;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @Configuration 
 * - 이 클래스가 "스프링 설정 클래스"임을 의미
 * - @Bean 메서드에서 반환하는 객체들이 스프링 컨테이너(ApplicationContext)에 등록됨
 * 
 * @EnableConfigurationProperties
 *  - @ConfigurationProperties가 붙은 클래스들을 스프링이 자동으로 바인딩 + 검증하도록 활성화
 *  - 여기서는: {OtpProperties, AuthProperties}
 */
@Configuration
@EnableConfigurationProperties({
        OtpProperties.class, 
        AuthProperties.class
})
public class AuthModuleConfig {

    // 서버 전체에서 사용할 표준 타임존(KST)
    private static final ZoneId KST = ZoneId.of("Asia/Seoul");

    @Bean
    public Clock clock() {
        return Clock.system(KST);
    }

    @Bean
    public SecureRandom secureRandom() {
        // getInstanceStrong()는 환경에 따라 느리거나 블로킹될 수 있어서 보통 new SecureRandom()이 낫다
        return new SecureRandom();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // ✅ 비밀번호 전용. OTP는 BCrypt로 하지 말고(느림) HMAC/SHA 계열로 별도 처리하는 게 좋다.
        return new BCryptPasswordEncoder();
    }
}
