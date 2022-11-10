package io.security.corespringsecurity.security.metadatasource;

import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/*
    인가처리를 위해 권한정보를 추출하기 위한 "FilterInvocationSecurityMetadataSource" 를 직접 구현해보기 !
     - FilterInvocationSecurityMetadataSource는 Map 객체에 담긴 권한정보를 추출하여 AccessDecisionManager 에게 전달하여 인가처리를 처리하도록 한다.
     - FilterInvocationSecurityMetadataSource는 를 구현하게 되면 Security설정 클래스에 인가 정책은 더 이상 동작하지 않는다.
 */
public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();

    private SecurityResourceService securityResourceService;

    public UrlFilterInvocationSecurityMetadataSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourcesMap , SecurityResourceService securityResourceService) {
        requestMap = resourcesMap; //DB로 부터 권한정보를 가져와 Map을 만든 UrlResourcesMapFactoryBean 클래스로 부터 Map 객체를 전달받는다.
        this.securityResourceService = securityResourceService;
    }

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


    /*
        DB에 있는 권한정보가 변경이나 추가가 일어났는때 어플리케이션을 재시작하지 않고 실시간적으로 반영시키기 위한 메소드드
    */
    public void reload() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadedMap = securityResourceService.getResourceList();
        Iterator<Map.Entry<RequestMatcher, List<ConfigAttribute>>> iterator = reloadedMap.entrySet().iterator();

        requestMap.clear();

        while (iterator.hasNext()) {
            Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
            requestMap.put(entry.getKey(), entry.getValue());
        }
    }
}
