package com.demosso.authorizationserver.controllers;

import com.demosso.authorizationserver.model.LoginRequest;
import com.demosso.authorizationserver.model.RegistrationRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String register() {
        return "register";
    }

    @GetMapping("/home")
    public String home(Model model) {
        return "home";
    }
}
