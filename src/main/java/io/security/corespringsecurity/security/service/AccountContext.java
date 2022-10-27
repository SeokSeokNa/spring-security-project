package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/*
    User 클래스는 UserDetails 인터페이스의 구현체이다!!
    스프링 시큐리티의 인증객체는 UserDetails 타입이기때문에 구현체인 User를 상속받아 커스텀 하여 사용한다.
 */
public class AccountContext extends User {


    private final Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;
    }

    //인증 객체를 꺼내오기 위해 getter 생성
    public Account getAccount() {
        return account;
    }
}
