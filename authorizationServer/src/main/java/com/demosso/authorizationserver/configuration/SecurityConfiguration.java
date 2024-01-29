package com.demosso.authorizationserver.configuration;

import com.demosso.authorizationserver.filter.BeforeAuthenticationFilter;
import com.demosso.authorizationserver.handler.LoginFailureHandler;
import com.demosso.authorizationserver.handler.LoginSuccessHandler;
import com.demosso.authorizationserver.security.socialLogin.SocialLoginAuthenticationSuccessHandler;
import com.demosso.authorizationserver.security.socialLogin.UserServiceOAuth2UserHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import static org.springframework.security.config.Customizer.withDefaults;

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
                    .successHandler(loginSuccessHandler)
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

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, /*BCryptPasswordEncoder bCryptPasswordEncoder,*/ UserDetailsService userDetailService)
            throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailService)
                //TODO add password encoder
                //.passwordEncoder(bCryptPasswordEncoder)
                .and()
                .build();
    }
}
