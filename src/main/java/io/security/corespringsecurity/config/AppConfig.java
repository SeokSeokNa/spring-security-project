package io.security.corespringsecurity.config;

import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/*
    공통 설정클래스
 */
@Configuration
public class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository) {
        SecurityResourceService securityResourceService = new SecurityResourceService(resourcesRepository);
        return securityResourceService;
    }
}
