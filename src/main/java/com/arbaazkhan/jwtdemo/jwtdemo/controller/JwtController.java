package com.arbaazkhan.jwtdemo.jwtdemo.controller;

import com.arbaazkhan.jwtdemo.jwtdemo.model.JwtRequest;
import com.arbaazkhan.jwtdemo.jwtdemo.model.JwtResponse;
import com.arbaazkhan.jwtdemo.jwtdemo.service.CustomUserDetailsService;
import com.arbaazkhan.jwtdemo.jwtdemo.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class JwtController {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/generateToken")
    public ResponseEntity<JwtResponse> generateToken(@RequestBody JwtRequest jwtRequest) {
        //first authenticate user
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(jwtRequest.getUserName(), jwtRequest.getPassword());
        authenticationManager.authenticate(token);
        //check for user existance
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(jwtRequest.getUserName());
        //generate token
        String jwtToken = jwtUtil.generateToken(userDetails);
        JwtResponse jwtResponse = new JwtResponse(jwtToken);
        return new ResponseEntity<>(jwtResponse, HttpStatus.OK);
    }

}
