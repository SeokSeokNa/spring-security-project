package io.security.corespringsecurity.security.factory;

import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;

/*
    FilterInvocationSecurityMetadataSource 클래스에서 권한정보를 추출하기 위한 requestMap 을 만드는 역활을 하게된다.
     - DB에서 직접 가지고 와서 권한정보 Map을 만들게된다.
 */
public class UrlResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher , List<ConfigAttribute>>> {

    private SecurityResourceService securityResourceService;
    private LinkedHashMap<RequestMatcher , List<ConfigAttribute>> resourceMap;


    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {

        if (resourceMap == null) {
            init();
        }

        return resourceMap;
    }

    //DB에서 인가처리를 위한 권한정보 가져오기 (path , authList)
    private void init() {
       resourceMap =  securityResourceService.getResourceList();
    }

    @Override
    public Class<?> getObjectType() {
        return null;
    }

    @Override
    public boolean isSingleton() {
        return true;
    }
}
