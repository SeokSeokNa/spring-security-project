package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/*
    Ajax 요청에 대한 인증을 처리하는 Provider
 */
public class AjaxAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    //검증
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();


        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);

        //비밀번호 암호화값 비교
        if (!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException("BadCredentialsException!");
        }



        //최종 인증객체 생성성
        AjaxAuthenticationToken authenticationToken = new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        return authenticationToken;
    }

    //인증객체의 타입이 AjaxAuthenticationToken 경우 판단
    //AjaxAuthenticationToken 타입일 경우만 인증 처리하도록
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AjaxAuthenticationToken.class);
    }
}
