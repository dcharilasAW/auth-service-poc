package com.demosso.authorizationserver.filter;

import com.demosso.authorizationserver.domain.User;
import com.demosso.authorizationserver.service.UserService;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

import java.io.UnsupportedEncodingException;

@Component
public class BeforeAuthenticationFilter
        extends UsernamePasswordAuthenticationFilter {

    @Autowired
    private UserService userService;

    @Autowired
    public void setAuthenticationManager(AuthenticationManager authManager) {
        super.setAuthenticationManager(authManager);
    }

    @Autowired
    @Override
    public void setAuthenticationFailureHandler(
            AuthenticationFailureHandler failureHandler) {
        super.setAuthenticationFailureHandler(failureHandler);
    }

    @Autowired
    @Override
    public void setAuthenticationSuccessHandler(
            AuthenticationSuccessHandler successHandler) {
        super.setAuthenticationSuccessHandler(successHandler);
    }

    public BeforeAuthenticationFilter() {
        setUsernameParameter("username");
        super.setRequiresAuthenticationRequestMatcher(
                new AntPathRequestMatcher("/login", "POST"));
    }

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        String email = request.getParameter("username");
        User user = userService.getByUsername(email);

        if (user != null) {
            if (user.isOTPRequired()) {
                return super.attemptAuthentication(request, response);
            }
            logger.info("attemptAuthentication - email: " + email);
            //float spamScore = getGoogleRecaptchaScore();

            //if (spamScore < 0.5) {
                userService.generateOneTimePassword(user);
                throw new InsufficientAuthenticationException("OTP");
            //}
        }
        return super.attemptAuthentication(request, response);
    }

    /*private float getGoogleRecaptchaScore() {
        //TODO call Google RECAPTHA API. For now hardcoded.
        return 0.43f;
    }*/

}
