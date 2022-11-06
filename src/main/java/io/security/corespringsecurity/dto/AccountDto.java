package io.security.corespringsecurity.dto;

import lombok.Data;

import java.util.List;

@Data
public class AccountDto {

    private Long id;
    private String username;
    private String password;
    private String email;
    private String age;
    private List<String> roles;
}
