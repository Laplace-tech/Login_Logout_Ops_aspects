package com.kyonggi.backend.auth.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.ZoneId;

@Configuration
@EnableConfigurationProperties(OtpProperties.class)
public class AuthModuleConfig {

    @Bean
    public ZoneId zoneId() {
        return ZoneId.of("Asia/Seoul");
    }

    @Bean
    public Clock clock(ZoneId zoneId) {
        return Clock.system(zoneId);
    }

    @Bean
    public SecureRandom secureRandom() {
        // getInstanceStrong()는 환경에 따라 느리거나 블로킹될 수 있어서 보통 new SecureRandom()이 낫다
        return new SecureRandom();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // 비밀번호/OTP 모두에 사용 중. (원하면 OTP 전용 해셔로 분리 가능)
        return new BCryptPasswordEncoder();
    }
}
