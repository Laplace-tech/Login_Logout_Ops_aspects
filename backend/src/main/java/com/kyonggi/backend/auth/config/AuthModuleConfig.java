package com.kyonggi.backend.auth.config;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.ZoneId;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableConfigurationProperties(OtpProperties.class)
public class AuthModuleConfig {

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
