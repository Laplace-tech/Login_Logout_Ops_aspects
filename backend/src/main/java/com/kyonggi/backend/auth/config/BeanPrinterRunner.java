package com.kyonggi.backend.auth.config;

import java.util.Arrays;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class BeanPrinterRunner implements CommandLineRunner {
    
    private final ApplicationContext applicationContext;

@Override
    public void run(String... args) throws Exception {
        log.info("=============================================");
        log.info("       Registered Beans (Filtered)           ");
        log.info("=============================================");

        String[] beanNames = applicationContext.getBeanDefinitionNames();
        
        // 이름순 정렬
        Arrays.sort(beanNames);

        for (String beanName : beanNames) {
            Object bean = applicationContext.getBean(beanName);
            String className = bean.getClass().getName();

            // 필터링: 내 패키지(com.kyonggi) 밑에 있는 것만 출력
            // (이 조건문을 빼면 스프링 내부 빈까지 수백 개가 다 나옴)
            if (className.startsWith("com.kyonggi")) {
                log.info("Bean Name: {:<30} | Class: {}", beanName, className);
            }
        }
        log.info("=============================================");
    }


}
