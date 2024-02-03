package com.demosso.authorizationserver.controllers;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@Slf4j
public class LogoutController {

    @RequestMapping("/exit")
    public ModelAndView exit(HttpServletRequest request, ModelMap model) {
        // token can be revoked here if needed
        new SecurityContextLogoutHandler().logout(request, null, null);
        return new ModelAndView("redirect:/init", model);
    }
}