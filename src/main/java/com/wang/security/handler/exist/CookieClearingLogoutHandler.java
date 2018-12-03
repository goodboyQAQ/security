package com.wang.security.handler.exist;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;

public final class CookieClearingLogoutHandler implements LogoutHandler {
    private final List<String> cookiesToClear;

    public CookieClearingLogoutHandler(String... cookiesToClear) {
        Assert.notNull(cookiesToClear, "cookie集合不能为空");
        this.cookiesToClear = Arrays.asList(cookiesToClear);
    }

    public void logout(HttpServletRequest request, HttpServletResponse response,
                       Authentication authentication) {
        for (String cookieName : cookiesToClear) {
            Cookie cookie = new Cookie(cookieName, null);
            String cookiePath = request.getContextPath() + "/";
            //正常的cookie只能在一个应用中共享，即一个cookie只能由创建它的应用获得。
            //同一服务器下可能有两个应用，通过setPath（）使path下都可以使用
            cookie.setPath(cookiePath);
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        }
    }
}
