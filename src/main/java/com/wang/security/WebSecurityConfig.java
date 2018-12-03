package com.wang.security;


import com.wang.security.filter.*;
import com.wang.security.handler.MyAccessDeniedHandler;
import com.wang.security.handler.MyAuthenticationEntryPoint;
import com.wang.security.handler.MyAuthenticationFailureHandler;
import com.wang.security.handler.MyAuthenticationSuccessHandler;
import com.wang.security.service.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtUserDetailsService userDetailsService;


    @Autowired
    JWTFilter jwtFilter;

    @Autowired
    UrlFilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource;
    @Autowired
    UrlAccessDecisionManager urlAccessDecisionManager;

    @Autowired
    MyAccessDeniedHandler myAccessDeniedHandler;
    @Autowired
    MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;
    @Autowired
    MyAuthenticationFailureHandler myAuthenticationFailureHandler;
    @Autowired
    MyAuthenticationEntryPoint myAuthenticationEntryPoint;



    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/demo/b");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O o) {
                        o.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource);
                        o.setAccessDecisionManager(urlAccessDecisionManager);
                        return o;
                    }
                })
        .and().formLogin()
                .loginProcessingUrl("/demo/login").permitAll()
                .failureHandler(myAuthenticationFailureHandler)
                .successHandler(myAuthenticationSuccessHandler)
        .and().logout().permitAll()
        .and().csrf().disable().exceptionHandling().accessDeniedHandler(myAccessDeniedHandler);
    }



    @Autowired
    public void configureAuthentication(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        //默认使用DaoAuthenticationProvider做登陆认证
        //authenticationManagerBuilder.userDetailsService(this.userDetailsService).passwordEncoder(passwordEncoder());

        //可以添加多个AuthenticationProvider
        authenticationManagerBuilder.authenticationProvider(new CustomAuthenticationProvider(userDetailsService,passwordEncoder()));
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
//    @Bean
//    public JWTFilter authenticationTokenFilterBean() throws Exception {
//        return new JWTFilter();
//    }

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
////        http.authorizeRequests()
////                .antMatchers("/demo/**").permitAll()
////                .antMatchers("/resources/**", "/signup", "/about").permitAll()
////                //hasRole自定加上ROLE_前缀
////                .antMatchers("/admin/**").hasRole("ADMIN")
////                //拥有其中一个角色就行
////                .antMatchers("/admin").hasAnyRole("ADMIN","USER")
////                //必须同时拥有
////                .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
////                .anyRequest().authenticated()//未指定的请求都要求用户进行身份验证
////            .and().formLogin()  //允许用户使用基于表单的登录进行身份验证
////                .loginPage("/login")  //指定登陆页面
////                .permitAll()  //授权所有用户
////            .and().httpBasic(); //允许用户使用HTTP基本身份验证进行身份验证
////        http.sessionManagement().sessionCreationPolicy(STATELESS); //不需要session
////        http.csrf().disable();; //关闭csrf防护
//        http
//                // 由于使用的是JWT，我们这里不需要csrf
//                .csrf().disable()
//
//                // 基于token，所以不需要session
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
//
//                .authorizeRequests()
//                //.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
//                .antMatchers("/demo/**").permitAll()
//                // 允许对于网站静态资源的无授权访问
//                .antMatchers(
//                        HttpMethod.GET,
//                        "/",
//                        "/*.html",
//                        "/favicon.ico",
//                        "/**/*.html",
//                        "/**/*.css",
//                        "/**/*.js"
//                ).permitAll()
//                // 对于获取token的rest api要允许匿名访问
//                .antMatchers("/auth/**").permitAll()
//                // 除上面外的所有请求全部需要鉴权认证
//                .anyRequest().authenticated();
//
//        // 禁用缓存
//        http.headers().cacheControl();
//
//        //添加jwt过滤器
//        http.addFilter(new JWTLoginFilter(authenticationManager()));
//       http.addFilterAfter(jwtFilter, UsernamePasswordAuthenticationFilter.class);
//
//
//
////        http.logout()  //注销支持
////                .logoutUrl("/my/logout")  //注销请求
////                //注销后重定向 默认是/login?logout   有已实现的SimpleUrlLogoutSuccessHandler
////                .logoutSuccessUrl("/my/index")
////                .logoutSuccessHandler(logoutSuccessHandler) //logoutSuccessUrl()将被忽略
////                .invalidateHttpSession(true)  //指定HttpSession注销后是否无效，默认true
////                .addLogoutHandler(logoutHandler) //已实现的SecurityContextLogoutHandler会被默认添加为最后一个handler
////                //注销成功后删除cookie, 有已实现的 CookieClearingLogoutHandler
////                .deleteCookies(cookieNamesToClear);
//
//
////        http.oauth2Client()
////                .clientRegistrationRepository(this.clientRegistrationRepository())
////                .authorizedClientRepository(this.authorizedClientRepository())
////                .authorizedClientService(this.authorizedClientService())
////                .authorizationCodeGrant()
////                .authorizationRequestRepository(this.authorizationRequestRepository())
////                .authorizationRequestResolver(this.authorizationRequestResolver())
////                .accessTokenResponseClient(this.accessTokenResponseClient());
//    }
}