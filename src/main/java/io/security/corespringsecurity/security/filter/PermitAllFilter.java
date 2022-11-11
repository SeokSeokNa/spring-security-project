package io.security.corespringsecurity.security.filter;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/*
    권한 검사가 필요없는 , 즉 모두에게 공개할 자원에 대해서는 통과시키기 위한 필터
    이렇게 구현 안해도 통과는 되지만 괜히 인가처리 과정을 겪고나서 이후에 통과 시키기 때문에 불필요한 작업을 없애기 위함이 크다.

    인가처리 순서
     1. FilterSecurityInterceptor 가 자신의 부모 클래스인 AbstraceSecurityInterceptor 에게 인가처리를 맡김
     2. AbstraceSecurityInterceptor 가 해당 자원에 대한 권한정보를 찾음
     3. 존재하면 해당 유저 권한과 비교하여 인가처리 , 존재하지 않으면 permitAll 효과로 다음필터로 보내 최종적으론 통과시킴
      FilterSecurityInterceptor -> AbstraceSecurityInterceptor -> List<권한정보> -> 권한심사후 유저 권한이 맞지않으면 AccessDecisionManager 호출
       권한자체가 없으면 통과
 */
public class PermitAllFilter extends FilterSecurityInterceptor {


    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
    private boolean observeOncePerRequest = true;

    //인증 및 권한이 필요없는 자원정보를 담은 리스트
    private List<RequestMatcher> permitAllRequestMatchers = new ArrayList<>();

    public PermitAllFilter(String... permitAllResources) {

        for (String resource : permitAllResources) {
            permitAllRequestMatchers.add(new AntPathRequestMatcher(resource));
        }
    }

    @Override
    protected InterceptorStatusToken beforeInvocation(Object object) {

        boolean permitAll = false;
        HttpServletRequest request = ((FilterInvocation) object).getRequest(); //사용자 요청정보 가져오기
        for (RequestMatcher requestMatcher : permitAllRequestMatchers) {
            if (requestMatcher.matches(request)) { // 인증및 권한이 필요없는 리스트 모음에서 사용자가 요청한 정보랑 같은게 있는지
                permitAll = true;
                break;
            }
        }

        if (permitAll) {
            return null; //인증 및 인가 통과 시키기 위해 null 리턴하기
        }

        return super.beforeInvocation(object);//위에 null로 리턴이 안됐다는것은 사용자가 요청한 해당 자원이 권한이나 인증이 필요하다는 것으로 인가처리하기
    }

    public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
        if (this.isApplied(filterInvocation) && this.observeOncePerRequest) {
            filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
        } else {
            if (filterInvocation.getRequest() != null && this.observeOncePerRequest) {
                filterInvocation.getRequest().setAttribute("__spring_security_filterSecurityInterceptor_filterApplied", Boolean.TRUE);
            }

            //부모 클래스를 호출하여 인가처리 하는 코드
//            InterceptorStatusToken token = super.beforeInvocation(filterInvocation);
            InterceptorStatusToken token = beforeInvocation(filterInvocation);

            try {
                filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
            } finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, (Object)null);
        }
    }

    private boolean isApplied(FilterInvocation filterInvocation) {
        return filterInvocation.getRequest() != null && filterInvocation.getRequest().getAttribute("__spring_security_filterSecurityInterceptor_filterApplied") != null;
    }

    public boolean isObserveOncePerRequest() {
        return this.observeOncePerRequest;
    }

    public void setObserveOncePerRequest(boolean observeOncePerRequest) {
        this.observeOncePerRequest = observeOncePerRequest;
    }
}
