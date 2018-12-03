package com.wang.security.bean;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;

@Data
@NoArgsConstructor
public class User {
    private String id;
    private String username;
    private String password;
    private String email;
    private List<String> roles;
    private Date lastPasswordResetDate;
}
