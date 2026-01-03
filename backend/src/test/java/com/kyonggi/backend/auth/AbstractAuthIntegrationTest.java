package com.kyonggi.backend.auth;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.kyonggi.backend.AbstractIntegrationTest;
import com.kyonggi.backend.auth.domain.User;
import com.kyonggi.backend.auth.repo.EmailOtpRepository;
import com.kyonggi.backend.auth.repo.UserRepository;
import com.kyonggi.backend.auth.token.repo.RefreshTokenRepository;


/**
 * Auth(회원/인증) 관련 통합테스트 공통 베이스
 * 
 * - Auth 관련 통합 테스트에서 매번 반복되는 "DB 초기화 + 기본 유저 생성"을 공통화한 클래스
 * - 매 테스트마다 동일한 초기 상태를 보장해야 안정적인 통합 테스트가 됨
 * - 개별 테스트 클래스에서 extends 하여 그대로 사용
 */
@Testcontainers
@AutoConfigureMockMvc
public abstract class AbstractAuthIntegrationTest extends AbstractIntegrationTest {
    
    protected static final String EMAIL = "add28482848@kyonggi.ac.kr";
    protected static final String PASSWORD = "28482848a!";
    protected static final String NICKNAME = "Anna";

    @Autowired protected UserRepository userRepository;
    @Autowired protected RefreshTokenRepository refreshTokenRepository;
    @Autowired protected EmailOtpRepository emailOtpRepository;
    @Autowired protected PasswordEncoder passwordEncoder;

    @BeforeEach
    void cleanDbAndSeedUser() {
        refreshTokenRepository.deleteAll();
        emailOtpRepository.deleteAll();
        userRepository.deleteAll();

        userRepository.save(User.create(
                EMAIL,
                passwordEncoder.encode(PASSWORD), // 비밀번호 암호화
                NICKNAME
        ));
    }


}
