package com.demosso.authorizationserver.handler;

import com.demosso.authorizationserver.domain.User;
import com.demosso.authorizationserver.service.ClientService;
import com.demosso.authorizationserver.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Autowired
    private UserService userService;

    @Autowired
    private ClientService clientService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        String username = (String) ((UsernamePasswordAuthenticationToken) authentication.getPrincipal()).getPrincipal();
        //TODO get client somehow, for now hardcoded
        String clientId = "demo-client"; //(String) ((UsernamePasswordAuthenticationToken) authentication.getRegisteredClient()).getId();
        RegisteredClient registeredClient = clientService.getByClientId(clientId);
        User user = userService.getByUsernameAndClient(username, registeredClient.getId());

        if (user.isOTPRequired()) {
            userService.clearOTP(user);
        }

        //response.sendRedirect("/foo");
        super.setDefaultTargetUrl("/foo");
        super.setAlwaysUseDefaultTargetUrl(true);
        super.onAuthenticationSuccess(request, response, authentication);
    }

}