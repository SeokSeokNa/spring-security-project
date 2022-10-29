package io.security.corespringsecurity.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
    인증의 성공 후 처리를 담당하는 Handler
 */
@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        //기본 타겟 URL 설정
        setDefaultTargetUrl("/");

        //인증하기 이전에 요청한 자원의 정보를 세션으로 부터 가져오기
        SavedRequest savedRequest = requestCache.getRequest(request,response);
        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();// 인증이전에 가고자 했던 URL 정보
            redirectStrategy.sendRedirect(request,response,targetUrl);
        } else {
            redirectStrategy.sendRedirect(request,response,getDefaultTargetUrl());
        }
    }
}
