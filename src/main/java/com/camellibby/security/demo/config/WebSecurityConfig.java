package com.camellibby.security.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;
import java.util.Collections;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private PasswordEncoder passwordEncoder;

//    @Autowired
    private DataSource dataSource;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .authorizeRequests()
                // 指定home页面可以匿名访问
                .antMatchers("/", "/home").permitAll()
                // 其它所有页面需要身份认证
                .anyRequest().authenticated()
            .and()
                // 采用httpBasic方式登录，也就是弹出一个用户名和密码的对话框
                //.httpBasic()
                // 采用form提交方式登录
                .formLogin()
                .loginPage("/login")
                .permitAll()
            .and()
                .logout()
                .permitAll();
        // @formatter:on
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /*
         * 第一种验证方式：自定义AuthenticationProvider
         */
//        auth.authenticationProvider(new AuthenticationProvider() {
//            @Override
//            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//                String username = authentication.getName();
//                if (authentication.getCredentials() == null) {
//                    throw new BadCredentialsException("Bad credentials");
//                }
//                String password = authentication.getCredentials().toString();
//                if ("admin".equals(username) && "123456".equals(password)) {
//                    UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
//                            authentication.getPrincipal(), authentication.getCredentials(),
//                            authentication.getAuthorities());
//                    result.setDetails(authentication.getDetails());
//                    return result;
//                }
//
//                throw new UsernameNotFoundException("用户或密码错误");
//            }
//
//            @Override
//            public boolean supports(Class<?> authentication) {
//                return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
//            }
//        });

        /*
         * 第二种验证方式：SpringSecurity的AuthenticationProvider 和 自定义UserDetailsService
         */
//        auth.userDetailsService(new UserDetailsService() {
//            @Override
//            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//                if ("admin".equals(username)) {
//                    return new User(
//                            "user",
//                            passwordEncoder.encode("123456"),
//                            Collections.singletonList(new SimpleGrantedAuthority("admin")
//                            ));
//                }
//                return null;
//            }
//        });

        /*
         * 第三种验证方式：SpringSecurity的AuthenticationProvider 和 SpringSecurity提供的UserDetailsService
         */
        /*
          第一种获取用户方式：使用内存中的用户信息，InMemoryUserDetailsManager
         */
        // @formatter:off
        auth
            .inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder.encode("123456"))
                .authorities("user")
            .and()
                .withUser("admin")
                .password(passwordEncoder.encode("123456"))
                .authorities("admin");
        // @formatter:on

        /*
         * 第二种获取用户方式：使用数据库中的用户信息，JdbcUserDetailsManager
         */
        // @formatter:off
//        auth
//            .jdbcAuthentication()
//                .dataSource(dataSource)
//                // 下面的方法会运行数据表初始化脚本，前提是你的数据库支持varchar_ignorecase字段类型
//                //.withDefaultSchema()
//                // 使用自定义sql查询用户信息
//                .usersByUsernameQuery("select username,password,enabled from users " + "where username = ?")
//            .withUser("user")
//                .password(passwordEncoder.encode("123456"))
//                .authorities("user")
//            .and()
//                .withUser("admin")
//                .password(passwordEncoder.encode("123456"))
//                .authorities("tester");
        // @formatter:on

        /*
         * 第三种验证方式：配置application.yml文件
         */
        // spring:
        //  security:
        //    user:
        //      name: admin
        //      password: 123456
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**", "/js/**", "/favicon.ico");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
