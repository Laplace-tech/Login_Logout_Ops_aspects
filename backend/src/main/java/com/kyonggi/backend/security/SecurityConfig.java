package com.kyonggi.backend.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

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
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable()) // CSRF 비활성화 - 세션/쿠키 기반 인증을 쓰지 않기 때문에 필요 없음
                .httpBasic(b -> b.disable()) // HTTP Basic 인증 비활성화 - Authorization: Basic ... 방식 사용 안 함
                .formLogin(f -> f.disable()) // formLogin 비활성화 - 스프링 기본 로그인 페이지 사용 안 함
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 사용 안 함 - 로그인 상태를 서버 세션에 저장하지 않음
                
                // 인증이 안 된 상태로 보호된 리소스 접근 시 어떻게 응답할지
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(new RestAuthEntryPoint(objectMapper))
                )

                // JWT 필터 등록:
                // UsernamePasswordAuthenticationFilter 전에 실행되도록 설정
                .addFilterBefore(
                        new JwtAuthenticationFilter(jwtService, objectMapper),
                        UsernamePasswordAuthenticationFilter.class
                )

                // 요청별 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll() // 스프링 내부 에러 페이지 접근 허용

                        // 공개 auth 엔드포인트만 permitAll
                        .requestMatchers("/auth/signup/**").permitAll()
                        .requestMatchers("/auth/login").permitAll()
                        .requestMatchers("/auth/refresh").permitAll()
                        .requestMatchers("/auth/logout").permitAll()

                        // 공개 조회 API
                        .requestMatchers(HttpMethod.GET, "/posts/**", "/categories/**").permitAll() // 조회 전용 API는 비로그인 허용
                        
                        // 나머지는 인증 필요 (/auth/me 포함)
                        .anyRequest().authenticated() // 그 외 모든 요청은 인증 필요
                )
                .build(); // SecurityFilterChain 생성
    }
}
