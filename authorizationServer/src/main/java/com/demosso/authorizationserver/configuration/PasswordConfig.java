package com.demosso.authorizationserver.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {

    @Bean
    public PasswordEncoder oauthClientPasswordEncoder(@Value("${ctp.auth.hash.strength}") int bcryptStrength) {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        //TODO update password encoding
        //return new BCryptPasswordEncoder(bcryptStrength);
    }
}
