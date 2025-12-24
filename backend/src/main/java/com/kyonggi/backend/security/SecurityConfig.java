package com.kyonggi.backend.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security 전역 보안 설정 클래스
 * 
 *  1) @Configuration 
 *  - 이 클래스가 "스프링 설정 클래스"임을 의미
 *  - 내부에 정의된 @Bean 메서드들이 스프링 컨테이너에 등록됨
 * 
 *  2) Spring Security 동작 구조
 *  - 모든 HTTP 요청은 @Controller에 도달하기 전에 "Security Filter Chain"을 먼저 통과함
 *  - 인증/인가 실패 시 @Controller 까지 도달하지 못함
 * 
 *  3) SecurityFilterChain
 *  - 여러 보안 필터(Authentication, Authorization)의 묶음
 *  - 어떤 요청을 허용/차단할지 이 체인에서 결정
 */
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable()) // CSRF 비활성화 - 세션/쿠키 기반 인증을 쓰지 않기 때문에 필요 없음
                .httpBasic(b -> b.disable()) // HTTP Basic 인증 비활성화 - Authorization: Basic ... 방식 사용 안 함
                .formLogin(f -> f.disable()) // formLogin 비활성화 - 스프링 기본 로그인 페이지 사용 안 함
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 사용 안 함 - 로그인 상태를 서버 세션에 저장하지 않음
                
                // 요청별 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll() // 스프링 내부 에러 페이지 접근 허용
                        .requestMatchers("/auth/signup/**").permitAll() // 회원가입 관련 API 전부 공개
                        .requestMatchers("/auth/login").permitAll() // 로그인 API 공개
                        // 내일 구현할 예정: 토큰 재발급, 로그아웃
                        // .requestMatchers("/auth/refresh", "/auth/logout").permitAll()

                        .requestMatchers(HttpMethod.GET, "/posts/**", "/categories/**").permitAll() // 조회 전용 API는 비로그인 허용
                        .anyRequest().authenticated() // 그 외 모든 요청은 인증 필요
                )
                .build(); // SecurityFilterChain 생성
    }
}
