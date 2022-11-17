package io.security.corespringsecurity.security.factory;

import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;

public class MethodResoucesFactoryBean implements FactoryBean<LinkedHashMap<String , List<ConfigAttribute>>> {

    private SecurityResourceService securityResourceService;
    private LinkedHashMap<String , List<ConfigAttribute>> resourceMap;
    private String resourceType;


    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    @Override
    public LinkedHashMap<String, List<ConfigAttribute>> getObject() {

        if (resourceMap == null) {
            init();
        }

        return resourceMap;
    }

    //DB에서 인가처리를 위한 권한정보 가져오기 (path , authList)
    private void init() {
        if ("method".equals(resourceType)) {
            resourceMap =  securityResourceService.getMethodResourceList();
        } else if("pointcut".equals(resourceType)) {
            resourceMap =  securityResourceService.getPointcutResourceList();
        }

    }

    @Override
    public Class<?> getObjectType() {
        return LinkedHashMap.class;
    }

    @Override
    public boolean isSingleton() {
        return true;
    }
}

