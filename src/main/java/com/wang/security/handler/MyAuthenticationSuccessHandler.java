package com.wang.security.handler;

import com.alibaba.fastjson.JSON;
import com.wang.security.bean.Result;
import com.wang.security.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Autowired
    JWTUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        UserDetails user = (UserDetails) authentication.getPrincipal();
        String jwtToken = jwtUtil.generateToken(user);
        List<String> data=new ArrayList<>();
        data.add(jwtToken);

        Result result=new Result(true,"登出成功");
        result.setData(data);
        response.getWriter().write(JSON.toJSONString(result));
    }
}
