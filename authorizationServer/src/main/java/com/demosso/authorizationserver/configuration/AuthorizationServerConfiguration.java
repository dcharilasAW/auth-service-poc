package com.demosso.authorizationserver.configuration;

import com.demosso.authorizationserver.model.mixin.CustomUserDetailsMixin;
import com.demosso.authorizationserver.model.mixin.OAuth2ClientAuthenticationTokenMixin;
import com.demosso.authorizationserver.security.CustomUserDetails;
import com.demosso.authorizationserver.security.grantPassword.GrantPasswordAuthenticationProvider;
import com.demosso.authorizationserver.security.grantPassword.OAuth2GrantPasswordAuthenticationConverter;
import com.demosso.authorizationserver.service.ClientService;
import com.demosso.authorizationserver.service.impl.CustomUserDetailsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.lang.reflect.Field;
import java.util.List;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    private OAuth2GrantPasswordAuthenticationConverter converter;

    public AuthorizationServerConfiguration(OAuth2GrantPasswordAuthenticationConverter converter) {
        this.converter = converter;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationSecurityFilterChain(
        HttpSecurity http,
        GrantPasswordAuthenticationProvider grantPasswordAuthenticationProvider,
        DaoAuthenticationProvider daoAuthenticationProvider
    ) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
            .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .tokenEndpoint(tokenEndpoint ->
                tokenEndpoint
                    .accessTokenRequestConverter(converter)
                    .authenticationProvider(grantPasswordAuthenticationProvider)
                    .authenticationProvider(daoAuthenticationProvider)
            )
            .oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0

        http
            .exceptionHandling(
                exceptions ->
                    exceptions.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/login")
                    )
            );

        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(
        PasswordEncoder passwordEncoder, UserDetailsService userDetailsService
    ) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        return daoAuthenticationProvider;
    }

    @Bean
    public GrantPasswordAuthenticationProvider grantPasswordAuthenticationProvider(
            CustomUserDetailsService userDetailsService, OAuth2TokenGenerator<?> jwtTokenCustomizer,
            OAuth2AuthorizationService authorizationService, PasswordEncoder passwordEncoder,
            ClientService clientService
    ) {
        return new GrantPasswordAuthenticationProvider(
            authorizationService, jwtTokenCustomizer, userDetailsService, passwordEncoder, clientService
        );
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {

        JdbcOAuth2AuthorizationService authorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModules(new CoreJackson2Module());
        objectMapper.registerModules(SecurityJackson2Modules.getModules(classLoader));
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        objectMapper.addMixIn(OAuth2ClientAuthenticationToken.class, OAuth2ClientAuthenticationTokenMixin.class);
        objectMapper.addMixIn(CustomUserDetails.class, CustomUserDetailsMixin.class);
        rowMapper.setObjectMapper(objectMapper);
        authorizationService.setAuthorizationRowMapper(rowMapper);
        return authorizationService;
        //return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, /*BCryptPasswordEncoder bCryptPasswordEncoder,*/
                                                       UserDetailsService userDetailService, GrantPasswordAuthenticationProvider grantPasswordAuthenticationProvider)
            throws Exception {
        AuthenticationManager authManager =  http.getSharedObject(AuthenticationManagerBuilder.class)
                //.authenticationProvider(grantPasswordAuthenticationProvider)
                .userDetailsService(userDetailService)
                //TODO add password encoder
                //.passwordEncoder(bCryptPasswordEncoder)
                .and()
                .build();

        //TODO not sure if this is still needed, the reason was to remove the default provided, daoAuthenticationProvider
        Field field = authManager.getClass().getDeclaredField("providers");
        field.setAccessible(true);
        field.set(authManager, List.of(grantPasswordAuthenticationProvider));
        return authManager;
    }

}
