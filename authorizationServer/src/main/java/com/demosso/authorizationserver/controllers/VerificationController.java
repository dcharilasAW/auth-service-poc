package com.demosso.authorizationserver.controllers;

import com.demosso.authorizationserver.security.CustomUserDetails;
import com.demosso.authorizationserver.service.impl.CustomUserDetailsService;
import com.demosso.authorizationserver.service.impl.OtpServiceImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
public class VerificationController {

    private OtpServiceImpl otpService;
    private CustomUserDetailsService customUserDetailsService;

    public VerificationController(OtpServiceImpl otpService, CustomUserDetailsService customUserDetailsService) {
        this.otpService = otpService;
        this.customUserDetailsService = customUserDetailsService;
    }

    @PostMapping(path = "/verify/request", consumes = APPLICATION_JSON_VALUE, produces = APPLICATION_JSON_VALUE)
    public String verifyRequest() {
        CustomUserDetails userDetails = (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        otpService.generateOneTimePassword(userDetails.getUsername());
        return "{}";
    }

    @PostMapping(path = "/verify/{otp}", consumes = APPLICATION_JSON_VALUE, produces = APPLICATION_JSON_VALUE)
    public String verifyOtp(@PathVariable String otp) {
        CustomUserDetails userDetails = (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        otpService.verifyOneTimePassword(userDetails.getUsername(),otp);
        customUserDetailsService.verifyUser(userDetails.getUsername(), userDetails.getClientId());
        return "{}";
    }
}
