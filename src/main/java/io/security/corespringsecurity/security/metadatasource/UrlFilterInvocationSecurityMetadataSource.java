package io.security.corespringsecurity.security.metadatasource;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/*
    인가처리를 위해 권한정보를 추출하기 위한 "FilterInvocationSecurityMetadataSource" 를 직접 구현해보기 !
     - FilterInvocationSecurityMetadataSource는 Map 객체에 담긴 권한정보를 추출하여 AccessDecisionManager 에게 전달하여 인가처리를 처리하도록 한다.
 */
public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {

        HttpServletRequest request = ((FilterInvocation) object).getRequest(); //사용자의 자원 path 요청정보 꺼내오기( 권한정보가 들어있는 requestMap 안에 권한정보를 가져오기 위한 Key 역활을 하게됨)

        //권한정보 추출하기
        if (requestMap != null) {
            for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
                RequestMatcher matcher = entry.getKey();
                if (matcher.matches(request)) {
                    return entry.getValue();
                }
            }
        }

        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet();
        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : this.requestMap.entrySet()) {
            allAttributes.addAll(entry.getValue());
        }
        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        //메소드 방식이 아닌 URL 방식일경우 FilterInvocation 객체를 생성해서 넘어오기에 URL 방식인지 판단할 수 있다.
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
