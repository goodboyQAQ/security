package com.wang.security.filter;

import com.wang.security.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JWTFilter extends OncePerRequestFilter {

    @Value("${jwt.header}")
    private String tokenHeader;

    @Value("${jwt.tokenHead}")
    private String tokenHead;

    @Autowired
    JWTUtil jwtUtil;

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    public void  doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        final String authHeader=request.getHeader(tokenHeader);
        String s= request.getRequestURI();
        if ("OPTIONS".equals(request.getMethod())) {//options请求直接返回200状态码
            response.setStatus(HttpServletResponse.SC_OK);
            chain.doFilter(request, response);
        }else{
            if (authHeader == null || !authHeader.startsWith(tokenHead)) {
                throw new ServletException("Missing or invalid Authorization header");
            }
            final String token = authHeader.substring(tokenHead.length());
            String userName = jwtUtil.getUsernameFromToken(token);

            if(userName!=null && SecurityContextHolder.getContext().getAuthentication() == null){//校验通过
                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);//足够信任token的情况下，可以省略这一步
                if (jwtUtil.validateToken(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    logger.info("JwtAuthenticationTokenFilter[doFilterInternal]  authenticated user " + userName + ", setting security context");
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
            chain.doFilter(request, response);

        }

    }
}
