package com.demosso.authorizationserver.controllers;

import com.demosso.authorizationserver.domain.User;
import com.demosso.authorizationserver.model.mixin.RegistrationRequest;
import com.demosso.authorizationserver.service.impl.CustomUserDetailsService;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
public class RegistrationController {

    private CustomUserDetailsService customUserDetailsService;

    public RegistrationController(CustomUserDetailsService customUserDetailsService) {
        this.customUserDetailsService = customUserDetailsService;
    }

    @PutMapping(path = "/register", consumes = APPLICATION_JSON_VALUE)
    public String register(@RequestBody RegistrationRequest request) {
        User user = customUserDetailsService.registerUser(request);
        return "registered user with id " + user.getId();
    }
}
