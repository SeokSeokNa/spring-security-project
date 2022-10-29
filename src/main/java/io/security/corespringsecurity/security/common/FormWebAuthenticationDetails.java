package io.security.corespringsecurity.security.common;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

/*
    WebAuthenticationDetails 클래스는 Form 요청시 username, password 외에 추가적인 파라미터를 "request" 로 부터 전달받아 저장하여
    Authentication 객체안에 Details 객체에 저장된다,

    추가적인 파라미터를 저장하고 관리하는 역활을 한다.
 */
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("secret_key");
    }

    public String getSecretKey() {
        return secretKey;
    }
}
