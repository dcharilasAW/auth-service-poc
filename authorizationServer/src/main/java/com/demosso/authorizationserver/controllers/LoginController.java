package com.demosso.authorizationserver.controllers;

import com.demosso.authorizationserver.model.LoginRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
public class LoginController {

    @PostMapping(path = "/login", consumes = APPLICATION_JSON_VALUE)
    public String register(@RequestBody LoginRequest request) {
        //User user = customUserDetailsService.registerUser(request);
        //return "registered user with id " + user.getId();
        return "OK";
    }
}
