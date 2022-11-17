package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.factory.MethodResoucesFactoryBean;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.SneakyThrows;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Map;


@Configuration
@EnableGlobalMethodSecurity //Map 기반으로 할거기때문에 해당 어노테이션에서 설정할수 있는 방식을 모두 false로 해둠
/*
    메소드보안 시큐리티 설정 클래스


    시큐리티 초기화때 메소드기반의 방식이 초기화 되는과정

    1 .DefaultAdvisorAutoProxyCreator 가 현재 등록된 모든 Bean을 검사한다.
    2. MethodSecurityMetadataSourceAdvisor 를 통해 프록시 객체 생성
    3. MethodSecurityMetadataSourceAdvisor 는 MethodSecurityMetadataSourcePointCut 와 MethodSecurityInterceptor 두가지를 가지고 있음
    4. MethodSecurityInterceptor는 MapBaseMethodSecurityMetadataSource 가 가지고있는 Map 객체로 부터 인가처리 어드바이스를 등록한다.(key 값에 해당하는 메소드명을 가진 클래스를)


    메소드방식 인가처리 순서
    1. 자원에 요청
    2. MethodSecurityInterceptor 가 요청 정보를 가로챔
    3. MethodSecurityInterceptor 가 MapBasedMethodSecurityMetadataSource 에게 해당 자원에 대한 권한정보를 요청함
    4. MapBasedMethodSecurityMetadataSource 는 "MethodMap" 이라는 맵 객체를 (메소드명,권한정보리스트) 형태로 가지고 있다가 해당 자원에 대한 권한 정보를 추출함
       해당 자원에 대한 권한 정보가 있다면 AccessDecisionManager 에게 인가처리 위임 , 없다면 인가처리를 하지 않음(pass)
 */
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {


    @Autowired
    private SecurityResourceService securityResourceService;

    //해당 메소드를 구현하면 Map 기반의 클래스인 "MapBasedMethodSecurityMetadataSource" 객체를
    //"GlobalMethodSecurityConfiguration" 가 가지게 되고 이후에 메소드 기반의 인가처리를 해주게된다.
    @Override
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        return mapBasedMethodSecurityMetadataSource();
    }

    @Bean
    public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource()  {
        return new MapBasedMethodSecurityMetadataSource(methodResourcesMapFactoryBean().getObject());
    }

    @Bean
    public MethodResoucesFactoryBean methodResourcesMapFactoryBean() {

        MethodResoucesFactoryBean methodResoucesFactoryBean = new MethodResoucesFactoryBean();
        methodResoucesFactoryBean.setSecurityResourceService(securityResourceService);
        methodResoucesFactoryBean.setResourceType("method");
        return methodResoucesFactoryBean;
    }

    @Bean
    public MethodResoucesFactoryBean pointcutResourcesMapFactoryBean() {

        MethodResoucesFactoryBean methodResoucesFactoryBean = new MethodResoucesFactoryBean();
        methodResoucesFactoryBean.setSecurityResourceService(securityResourceService);
        methodResoucesFactoryBean.setResourceType("pointcut");
        return methodResoucesFactoryBean;
    }

    @Bean
    BeanPostProcessor protectPointcutPostProcessor() throws Exception {

        Class<?> clazz = Class.forName("org.springframework.security.config.method.ProtectPointcutPostProcessor");
        Constructor<?> declaredConstructor = clazz.getDeclaredConstructor(MapBasedMethodSecurityMetadataSource.class);
        declaredConstructor.setAccessible(true);
        Object instance = declaredConstructor.newInstance(mapBasedMethodSecurityMetadataSource());
        Method setPointcutMap = instance.getClass().getMethod("setPointcutMap", Map.class);
        setPointcutMap.setAccessible(true);
        setPointcutMap.invoke(instance, pointcutResourcesMapFactoryBean().getObject()); //db로 부터 가지고온 resourceMap 데이터가 전달됨

        return (BeanPostProcessor)instance;
    }
}
