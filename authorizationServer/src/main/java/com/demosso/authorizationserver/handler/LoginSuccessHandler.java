package com.demosso.authorizationserver.handler;

import com.demosso.authorizationserver.domain.User;
import com.demosso.authorizationserver.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Autowired
    private UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        //TODO missing client, for now load with default one
        User user = userService.getByUsername(userDetails.getUsername());

        if (user.isOTPRequired()) {
            userService.clearOTP(user);
        }

        //response.sendRedirect("/foo");
        super.setDefaultTargetUrl("/foo");
        super.setAlwaysUseDefaultTargetUrl(true);
        super.onAuthenticationSuccess(request, response, authentication);
    }

}