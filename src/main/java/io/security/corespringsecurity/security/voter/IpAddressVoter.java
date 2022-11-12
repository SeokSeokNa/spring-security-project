package io.security.corespringsecurity.security.voter;

import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

/*
    IP 접속 제한을 하기 위한 클래스
 */



public class IpAddressVoter implements AccessDecisionVoter<Object> {

    private  SecurityResourceService securityResourceService;


    public IpAddressVoter(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {

        WebAuthenticationDetails details = (WebAuthenticationDetails)authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();

        List<String> accessIpList = securityResourceService.getAccessIpList();

        int result = ACCESS_DENIED;

        for (String ipAddress : accessIpList) {
            if (remoteAddress.equals(ipAddress)) {
                result = ACCESS_ABSTAIN; // "ACCESS_GRANTED" 로 줘버리면 권한 검사없이 바로 통과 시키기 때문에 다음 심사를 위해 "ACCESS_ABSTAIN"을 준다.
            }
        }

        //다음심사 검사할 필요없이 모든 자원접근에 대해 차단하기 위해 예외를 터트린다.
        if (result == ACCESS_DENIED) {
            throw new AccessDeniedException("Invalid IpAddress");
        }

        return result;
    }
}
