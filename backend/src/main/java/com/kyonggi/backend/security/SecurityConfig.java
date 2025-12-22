package com.kyonggi.backend.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .httpBasic(b -> b.disable())
                .formLogin(f -> f.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll()

                        // ✅ signup/otp 관련만 열어두기 (나중에 /auth/me 생겨도 실수로 열리지 않게)
                        .requestMatchers("/auth/signup/**").permitAll()

                        // (로그인 구현하면 여기 3개도 permitAll로 추가 예정)
                        // .requestMatchers("/auth/login", "/auth/refresh", "/auth/logout").permitAll()

                        .requestMatchers(HttpMethod.GET, "/posts/**", "/categories/**").permitAll()
                        .anyRequest().authenticated()
                )
                .build();
    }
}
