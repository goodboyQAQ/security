package com.wang.security.handler;

import com.alibaba.fastjson.JSON;
import com.wang.security.bean.Result;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Component
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        Result result=new Result(false,"登陆失败");
        if (e instanceof UsernameNotFoundException || e instanceof BadCredentialsException) {
            result.setMsg("用户名或密码输入错误，登录失败!");
        } else if (e instanceof DisabledException) {
            result.setMsg("账户被禁用，登录失败，请联系管理员!");
        }
        response.getWriter().write(JSON.toJSONString(result));
    }
}
