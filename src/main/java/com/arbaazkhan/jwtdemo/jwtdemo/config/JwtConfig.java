package com.arbaazkhan.jwtdemo.jwtdemo.config;

import com.arbaazkhan.jwtdemo.jwtdemo.filter.JwtAuthenticationFilter;
import com.arbaazkhan.jwtdemo.jwtdemo.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class JwtConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtAuthenticationFilter jwtFilter;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    //we can control what will be our authentication mode, and we say how we want to manage our authentication process
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //We will create 1 service and will path the object of that service
        auth.userDetailsService(customUserDetailsService);
    }

    //With this method we will control which endpoints are permitted and which are not permitted
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //here we are writing what we want to block and allow from our http request
        http
                //cross site request forgery
                .csrf()
                .disable()
                //cross-origin resource sharing, allows access to our api from any domain. Disabling it will allow our api to be called from any domain, ex. say our api is hosted on www.myAPi.com, and we make call from localhost with cors disable we can make that call and get a successful return
                .cors()
                .disable()
                //what request are we going to allow
                .authorizeRequests()
                //which endpoints are we making "public"
                .antMatchers("/api/generateToken").permitAll()  //only allow this endpoint without authentication
                //for any other request we want it to be authenticated
                .anyRequest().authenticated() //will be authenticated by calling CustomUserDetailService.loadUserByUsername()
                .and()
                //want sessionManagement to be stateless. the server will not keep track requests coming from the client
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //Every request should be independent of others and server does not have to manage session

        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }

    //secure our passwords
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
