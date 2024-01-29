package com.demosso.authorizationserver.handler;

import com.demosso.authorizationserver.domain.User;
import com.demosso.authorizationserver.service.UserService;
import com.demosso.authorizationserver.service.impl.CustomUserDetailsService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Autowired
    private UserService userService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response, AuthenticationException exception)
            throws IOException, ServletException {

        String email = request.getParameter("username");
        log.info("onAuthenticationFailure username: " + email);
        request.setAttribute("email", email);

        String redirectURL = "/login?error&username=" + email;

        if (exception.getMessage().contains("OTP")) {
            redirectURL = "/login?otp=true&username=" + email;
        } else {
            User user = userService.getByUsername(email);
            if (user.isOTPRequired()) {
                redirectURL = "/login?otp=true&username=" + email;
            }
        }

        super.setDefaultFailureUrl(redirectURL);
        super.onAuthenticationFailure(request, response, exception);
    }

}
