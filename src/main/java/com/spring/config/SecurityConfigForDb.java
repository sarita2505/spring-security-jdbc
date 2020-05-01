package com.spring.config;

import com.spring.handler.CustomAccessDeniedHandler;
import com.spring.handler.CustomAuthenticationFailureHandler;
import com.spring.handler.CustomAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.sql.DataSource;


@EnableWebSecurity
public class SecurityConfigForDb extends WebSecurityConfigurerAdapter {
    @Autowired
     DataSource dataSource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().dataSource(dataSource);

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/admin").hasRole("admin")
                .antMatchers("/user").hasAnyRole("admin", "user")
                .antMatchers("/", "/accessDenied", "/loginFailed").permitAll().anyRequest().authenticated()
                .and().
                formLogin().
                successHandler(new CustomAuthenticationSuccessHandler()).
                failureHandler(new CustomAuthenticationFailureHandler()).
                // defaultSuccessUrl("/", true).
                        and().
                exceptionHandling().
                accessDeniedHandler(accessDeniedHandler());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
       // return new BCryptPasswordEncoder();
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }
}
