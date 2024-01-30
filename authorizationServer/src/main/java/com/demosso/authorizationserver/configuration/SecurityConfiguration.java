package com.demosso.authorizationserver.configuration;

import com.demosso.authorizationserver.filter.BeforeAuthenticationFilter;
import com.demosso.authorizationserver.handler.LoginFailureHandler;
import com.demosso.authorizationserver.handler.LoginSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
        /*AuthenticationSuccessHandler authenticationSuccessHandler, */LoginFailureHandler loginFailureHandler,
                                                          LoginSuccessHandler loginSuccessHandler,
                                                          BeforeAuthenticationFilter beforeLoginFilter) throws Exception {
        /*return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/register").permitAll()
                        .anyRequest().authenticated()
                )
                //TODO login page does not send client, decide how to handle this
                .formLogin(withDefaults())
                .oauth2Login(oauth -> oauth.successHandler(authenticationSuccessHandler))
                .logout((logout) -> logout.permitAll())
                .csrf().disable()
                .build();*/

        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/register").permitAll()
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(beforeLoginFilter, BeforeAuthenticationFilter.class)
                .formLogin()
                    .loginPage("/login")
                    .usernameParameter("username")
                    .defaultSuccessUrl("/foo", true)
                    //.successHandler(loginSuccessHandler)
                    .failureHandler(loginFailureHandler)
                    .permitAll()
                /*.oauth2Login(oauth -> {
                    oauth.successHandler(loginSuccessHandler);
                    oauth.failureHandler(loginFailureHandler);
                })*/
                .and()
                .logout((logout) -> logout.permitAll())
                .csrf().disable()
                .build();
    }

    /*@Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(UserServiceOAuth2UserHandler handler) {
        SocialLoginAuthenticationSuccessHandler authenticationSuccessHandler =
            new SocialLoginAuthenticationSuccessHandler();
        authenticationSuccessHandler.setOidcUserHandler(handler);
        return authenticationSuccessHandler;
    }*/

}
