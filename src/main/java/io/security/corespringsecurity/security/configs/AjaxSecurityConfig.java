package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Order(1)
//Ajax 전용 Security 설정 클래스
public class AjaxSecurityConfig {


    @Bean
    public AuthenticationProvider  ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider();
    }

//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
//        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
//        authenticationManager.getProviders().add(ajaxAuthenticationProvider());
//        return authenticationManager;
//    }


    @Bean
    public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(ajaxAuthenticationProvider());
        // Get AuthenticationManager
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();



        return http
                .antMatcher("/api/**")
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .authenticationManager(authenticationManager)
                .addFilterBefore(ajaxLoginProcessingFilter(authenticationManager) , UsernamePasswordAuthenticationFilter.class)
                .csrf().disable()
                .build();
    }


    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter(AuthenticationManager authenticationManager) throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManager);
        return ajaxLoginProcessingFilter;
    }

}
