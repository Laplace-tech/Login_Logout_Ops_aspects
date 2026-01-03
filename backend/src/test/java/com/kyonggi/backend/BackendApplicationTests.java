package com.kyonggi.backend;

import org.junit.jupiter.api.Test;

/**
 * 스모크 테스트: 스프링 컨텍스트가 정상적으로 뜨는지 확인
 *
 * - 스프링 부트 ApplicationContext 로딩이 성공하는지만 확인
 * - 설정(yml), Bean 등록, 시크릿, DB 연결 등 "컨텍스트 로딩 단계"에서 터지는 문제를 가장 빨리 잡아줌
 *
 * [테스트 실행]:
 * - cd backend
 * - ./gradlew test --no-daemon
 *
 * [특정 테스트만 실행]:
 * - ./gradlew test --no-daemon --tests com.kyonggi.backend.BackendApplicationTests
 */
class BackendApplicationTests extends AbstractIntegrationTest {
   
   @Test 
   void contextLoads() {   
   }
   
}

