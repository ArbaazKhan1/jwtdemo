package com.arbaazkhan.jwtdemo.jwtdemo.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    //THis method actually does the validation for  user existence
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //ideally we would make a call to the repo and check if the username actually exists or not and fetch user details
        //for now we are keeping it simple
        if (username.equals("Arbaaz")) { //here you should make a DB call with the help of repository and do the validation
            //simple: we return provided default
            return new User("Arbaaz", "secret", new ArrayList<>()); //the 3rd param is actually the roles the user has
        } else {
            throw new UsernameNotFoundException("User does not exist");
        }
    }
}
