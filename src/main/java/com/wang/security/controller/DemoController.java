package com.wang.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo")
public class DemoController {

    @RequestMapping(value="/a",method = RequestMethod.GET)
    public String a(){
        return "a";
    }

    @RequestMapping(value="/b",method = RequestMethod.GET)
    public String b(){
        return "b";
    }

    @RequestMapping(value="login")
    public String login(){
        return "login";
    }
}
