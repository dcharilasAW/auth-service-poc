package com.demosso.resourceserver.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
        OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter
    ) throws Exception {
        http.oauth2ResourceServer(
          auth -> auth
              .opaqueToken(
                  opaqueTokenConfigurer -> opaqueTokenConfigurer
                      .introspectionUri("http://localhost:8080/oauth2/introspect")
                          //TODO change
                      .introspectionClientCredentials("demo-client", "demo-secret")
                      .authenticationConverter(opaqueTokenAuthenticationConverter)
              )
        );

        http.cors(httpSecurityCorsConfigurer -> corsConfigurationSource())
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(HttpMethod.OPTIONS).permitAll();//allow CORS option calls
                    auth.anyRequest().authenticated();
                }
        );

        return http.build();
    }

    @Bean
    public OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter() {
        return new CustomOpaqueTokenAuthenticationConverter();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE", "PATCH"));
        configuration.setAllowCredentials(false);

        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Accept",
                "Cache-Control",
                "Content-Type",
                "Origin",
                "x-csrf-token",
                "x-requested-with"
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


}
