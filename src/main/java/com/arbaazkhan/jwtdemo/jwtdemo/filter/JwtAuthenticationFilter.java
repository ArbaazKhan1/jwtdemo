package com.arbaazkhan.jwtdemo.jwtdemo.filter;

import com.arbaazkhan.jwtdemo.jwtdemo.service.CustomUserDetailsService;
import com.arbaazkhan.jwtdemo.jwtdemo.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//The extends makes it so the filter is only called once per request
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    CustomUserDetailsService customUserDetailsService;
    @Autowired
    JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //Get Jwt token from request header
        //validate the jwt token
        String bearerToken = request.getHeader("Authorization"); //extract authorization header
        String un = null;
        String token = null;
        //check if token exists or has bearer text
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            //extract jwt token from bearer token
            token = bearerToken.substring(7); //this sub string is cutting out the text from the if statement

            try {
                //extract userName from token
                un = jwtUtil.extractUsername(token);

                //get user details for this user
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(un);

                //security checks
                //if the username is not null and the security context is null then create a new security context object
                //this is standard code
                if(un!=null && SecurityContextHolder.getContext().getAuthentication() ==null) {
                    UsernamePasswordAuthenticationToken upat = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                    upat.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(upat);

                } else {
                    System.out.println("Invalid Token!");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Invalid Bearer Token Format");
        }

        //if all is well forward the filter request to the request endpoint
        filterChain.doFilter(request,response);
    }
}
