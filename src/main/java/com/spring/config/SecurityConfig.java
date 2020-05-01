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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.sql.DataSource;


//@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
     DataSource dataSource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().withDefaultSchema().dataSource(dataSource).
                withUser(
                        User.withUsername("ram").
                                password(passwordEncoder().encode("ram")).
                                roles("admin")
                ).
                withUser(
                        User.withUsername("sita").
                                password(passwordEncoder().encode("sita")).
                                roles("user")
                ).
                withUser(
                        User.withUsername("xyz").
                                password(passwordEncoder().encode("xyz")).
                                roles("any")
                );

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
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }
}
