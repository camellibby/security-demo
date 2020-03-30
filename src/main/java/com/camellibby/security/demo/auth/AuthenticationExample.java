package com.camellibby.security.demo.auth;

import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;

/**
 * @author luoxinliang
 */
public class AuthenticationExample {
    /**
     * 第一种方式：使用自定义AuthenticationManager
     */
    private static AuthenticationManager am = new SampleAuthenticationManager();

    /**
     * 第二种方式：使用SpringSecurity的AuthenticationManager 和 自定义AuthenticationProvider
     */
//    private static AuthenticationProvider provider = new SimpleAuthenticationProvider();
//    private static List<AuthenticationProvider> providers = Collections.singletonList(provider);
//    private static AuthenticationManager am = new ProviderManager(providers);

    /**
     * 第三种方式：使用SpringSecurity的AuthenticationManager 和 SpringSecurity的AuthenticationProvider
     */
//    private static List<AuthenticationProvider> providers = Collections.singletonList(getDaoAuthentication());
//    private static AuthenticationManager am = new ProviderManager(providers);

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

        while (true) {
            System.out.println("Please enter your username:");
            String name = in.readLine();
            System.out.println("Please enter your password:");
            String password = in.readLine();
            try {
                Authentication request = new UsernamePasswordAuthenticationToken(name, password);
                Authentication result = am.authenticate(request);
                SecurityContextHolder.getContext().setAuthentication(result);
                break;
            } catch (AuthenticationException e) {
                System.out.println("Authentication failed: " + e.getMessage());
            }
        }
        System.out.println("Successfully authenticated. Security context contains: " +
                SecurityContextHolder.getContext().getAuthentication());
    }

    private static AuthenticationProvider getDaoAuthentication() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder.encode("123456"))
                .authorities("ROLE_USER")
                .build();
        UserDetailsService uds = new InMemoryUserDetailsManager(admin);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(uds);
        return provider;
    }
}