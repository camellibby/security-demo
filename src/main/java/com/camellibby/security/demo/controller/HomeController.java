package com.camellibby.security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.Filter;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/")
public class HomeController {
    @Autowired
    @Qualifier(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
    public Filter springSecurityFilterChain;


    @GetMapping(value = "/filterChain")
    public String filterChain() {
        StringBuilder sb = new StringBuilder();
        FilterChainProxy filterChainProxy = (FilterChainProxy) springSecurityFilterChain;
        for (SecurityFilterChain filterChain : filterChainProxy.getFilterChains()) {
            DefaultSecurityFilterChain defaultSecurityFilterChain = (DefaultSecurityFilterChain)filterChain;
            sb.append("filter chain: " + defaultSecurityFilterChain.getRequestMatcher());
            sb.append("\r\n");
            sb.append("with filters: ");
            sb.append("\r\n");
            for (Filter filter : filterChain.getFilters()) {
                sb.append(filter.getClass());
                sb.append("\r\n");
            }
            sb.append("-----------------------------------------------------------");
            sb.append("\r\n");
        }
        return sb.toString();
    }

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

    @RequestMapping({"/user", "/me"})
    public Map<String, String> user(Principal principal) {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("name", principal.getName());
        return map;
    }
}
