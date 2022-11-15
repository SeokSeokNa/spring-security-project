package io.security.corespringsecurity.security.configs;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity //Map 기반으로 할거기때문에 해당 어노테이션에서 설정할수 있는 방식을 모두 false로 해둠
/*
    메소드보안 시큐리티 설정 클래스
 */
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {


    //해당 메소드를 구현하면 Map 기반의 클래스인 "MapBasedMethodSecurityMetadataSource" 객체를
    //"GlobalMethodSecurityConfiguration" 가 가지게 되고 이후에 메소드 기반의 인가처리를 해주게된다.
    @Override
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        return new MapBasedMethodSecurityMetadataSource();
    }
}
