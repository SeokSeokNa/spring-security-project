package io.security.corespringsecurity.security.common;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.net.http.HttpRequest;

/*
    WebAuthenticationDetails 클래스를 생성하는 역활을 한다.
    (나 같은경우 WebAuthenticationDetails를 상속받아 Custom한 FormWebAuthenticationDetails 클래스를 여기서 생성하도록 해야한다.)
 */
@Component
public class FormAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest , WebAuthenticationDetails> {


    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new FormWebAuthenticationDetails(context);
    }
}
