package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.common.FormAuthenticationDetailsSource;
import io.security.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.corespringsecurity.security.filter.PermitAllFilter;
import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.CustomAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.CustomAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import io.security.corespringsecurity.security.voter.IpAddressVoter;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@Slf4j
@RequiredArgsConstructor
@Order(0)
//@EnableGlobalMethodSecurity(securedEnabled = true , prePostEnabled = true) //????????? ????????? ??????????????? ?????? ????????? ???????????????
public class SecurityConfig {

    private final FormAuthenticationDetailsSource formAuthenticationDetailsSource;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    private final SecurityResourceService securityResourceService;

    private String[] permitAllResources = {"/", "/login", "/user/login/**"};

//    @Bean
//    public UserDetailsManager users() {
//
//        String password = passwordEncoder().encode("1111");
//
//        UserDetails user = User.builder()
//                .username("user")
//                .password(password)
//                .roles("USER")
//                .build();
//
//        UserDetails sys = User.builder()
//                .username("manager")
//                .password(password)
//                .roles("MANAGER" , "USER")
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password(password)
//                .roles("ADMIN" , "USER" , "MANAGER")
//                .build();
//
//        return new InMemoryUserDetailsManager(user, sys, admin);
//    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
        authenticationManager.getProviders().add(customAuthenticationProvider());
        return authenticationManager;
//        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http

                .authorizeRequests()
                .anyRequest().authenticated()
//                .antMatchers("/mypage").hasRole("USER")
//                .antMatchers("/messages").hasRole("MANAGER")
//                .antMatchers("/config").hasRole("ADMIN")
//                .antMatchers("/**").permitAll()
                /*
                    .antMatchers("/mypage").hasRole("MANAGER")
                     - ???????????? ????????? Map ????????? ???????????? key??? path?????? value??? Role ???(List???????????? -> ??????????????? ??????????????? ?????????) ????????????.
                     - ExpressionBasedFilterInvocationSecurityMetadataSource??? ?????? ???????????? DefaultFilterInvocationSecurityMetadataSource ??? ????????? ?????????
                       resultMap ????????? ???????????? ?????? Map ???????????? ??????????????? ??? ??? ??????.
                     - DefaultFilterInvocationSecurityMetadataSource ??????????????? "getAttributes" ???????????? ?????? ?????? ????????? ????????????.

                 */
                .and()
                .formLogin()
                .loginPage("/login")
//                .defaultSuccessUrl("/")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(formAuthenticationDetailsSource)
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .accessDeniedHandler(customAccessDeniedHandler)
                .and()
//                .authenticationManager(authenticationManager(http.getSharedObject(AuthenticationConfiguration.class)))
                .addFilterAt(customFilterSecurityInterceptor(http.getSharedObject(AuthenticationConfiguration.class)), FilterSecurityInterceptor.class)
                .csrf().disable()
                .build();
    }

    //webignore ??????(?????? ????????? ????????? ?????? ?????? ???????????? ??????)
    /*
        atCommonLocations() ???????????? ???????????? -> StaticResourceLocation ????????? ???????????? ignore ??? ????????? ???????????? path??? ????????????
        SecurityFilterChain ??? ???????????? ????????? webignore ???????????? ??? ??? ??????
        ?????????????????? SecurityFilterChain??? ????????? ?????? ?????? ??????????????? ????????? ?????? permitAll ??? ??????????????? ???????????? ???????????? ???????????? ?????????
        webignore ????????? ???????????? ????????? ???????????? ??????.
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PermitAllFilter customFilterSecurityInterceptor(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllResources);
        permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        permitAllFilter.setAccessDecisionManager(affirmativeBased());
        permitAllFilter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
        return permitAllFilter;
    }


    private AccessDecisionManager affirmativeBased() {
        AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecisionVoters());
        return affirmativeBased;
    }

    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {

        List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();

        /*
            voter ????????? "IpAddressVoter" ??? ?????? accessDecisionVoters??? ????????? ?????????
            ?????? ?????? ????????? ?????? ??????????????? , ?????? ???????????? ?????? ????????? ??? ?????? ??????????????? ???????????? ??????
            ????????? IpAddressVoter??? ???????????? ???????????? ???????????? ?????? voter?????? ACCESS_GRANTED??? ????????? ?????? ?????? ????????? ???????????? ????????? ??????????????????.
         */

//        accessDecisionVoters.add(new IpAddressVoter(securityResourceService));
        accessDecisionVoters.add(roleVoter());

        return accessDecisionVoters;
    }

    @Bean
    public AccessDecisionVoter<? extends Object> roleVoter() {

        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
        return roleHierarchyVoter;
    }



    @Bean
    public RoleHierarchyImpl roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        return roleHierarchy;
    }

    @Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
        return new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean().getObject() , securityResourceService);
    }

    private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {

        UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
        urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);

        return urlResourcesMapFactoryBean;
    }


}
