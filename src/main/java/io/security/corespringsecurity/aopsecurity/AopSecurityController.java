package io.security.corespringsecurity.aopsecurity;

import io.security.corespringsecurity.dto.AccountDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
/*
    메소드 권한으로 시큐리티 설정해보기
 */
//@EnableGlobalMethodSecurity(prePostEnabled = true , securedEnabled = true) // 메소드 권한방식을 사용할떄 꼭 이 어노테이션을 켜줘야 한다.
@RequiredArgsConstructor
public class AopSecurityController {

    private final AopMethodService aopMethodService;
    private final AopPointcutService aopPointcutService;

    private final AopLiveMethodService aopLiveMethodService;


    @GetMapping("/preAuthorize")
    @PreAuthorize("hasRole('ROLE_USER') and #account.username == principal.username") //#account 하면 account 객체를 참조할수 있게 해준다 , principal에는 로그인한 인증 정보가 들어있음
    public String preAuthorize(AccountDto account , Model model , Principal principal) {

        model.addAttribute("method", "Success @PreAuthorize");

        return "aop/method";
    }

    @GetMapping("/methodSecured")
    public String methodSecured(Model model) {
        aopMethodService.methodSecured();
        model.addAttribute("method", "Success MethodSecured");

        return "aop/method";
    }

    @GetMapping("/pointcutSecured")
    public String pointcutSecured(Model model) {
        aopPointcutService.notSecured();
        aopPointcutService.pointcutSecured();
        model.addAttribute("method", "Success MethodSecured");

        return "aop/method";
    }


    @GetMapping("/liveMethodSecured")
    public String liveMethodSecured(Model model){

        aopLiveMethodService.liveMethodSecured();
        model.addAttribute("method", "Success LiveMethodSecured");

        return "aop/method";
    }
}
