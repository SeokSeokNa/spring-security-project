package io.security.corespringsecurity.controller.login;

import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;

@Controller
public class LoginController {

    @GetMapping({"/login" , "/api/login"})
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "exception", required = false) String exception, Model model) {

        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
        return "user/login/login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "redirect:/login";
    }

    @GetMapping({"/denied" , "/api/denied"})
    public String accessDenied(@RequestParam(value = "exception", required = false) String exception, Principal principal, Model model) throws Exception {
          //전역적으로 접근 가능한 SecurityContextHolder 에서 인증객체 가져오기
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        Account account = (Account)authentication.getPrincipal();
//        model.addAttribute("username", account.getUsername());
//        model.addAttribute("exception",exception);


        Account account = null;

        if (principal instanceof UsernamePasswordAuthenticationToken) {
            account = (Account) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();

        }else if(principal instanceof AjaxAuthenticationToken){
            account = (Account) ((AjaxAuthenticationToken) principal).getPrincipal();
        }
        model.addAttribute("username", account.getUsername());
        model.addAttribute("exception", exception);


        return "user/login/denied";
    }
}
