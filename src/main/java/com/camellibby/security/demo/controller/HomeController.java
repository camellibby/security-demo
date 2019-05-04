package com.camellibby.security.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/")
public class HomeController {
    @GetMapping(value = {"/", "/home"})
    public ModelAndView home() {
        return new ModelAndView("home");
    }

    @GetMapping(value = "/hello")
    public ModelAndView hello() {
        return new ModelAndView("hello");
    }

    @GetMapping(value = "/login")
    public ModelAndView login() {
        return new ModelAndView("login");
    }

    @RequestMapping({ "/user", "/me" })
    public Map<String, String> user(Principal principal) {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("name", principal.getName());
        return map;
    }
}
