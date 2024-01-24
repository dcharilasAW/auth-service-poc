package com.demosso.authorizationserver.configuration.client;

import com.demosso.authorizationserver.security.grantPassword.AuthorizationGrantTypePassword;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class ClientsConfiguration {

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {

        RegisteredClient demoClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .id("2fbb93b1-8b4a-48ef-a75a-875078503a4d")
                .clientName("Demo client")
                .clientId("demo-client")

                // {noop} means "no operation," i.e., a raw password without any encoding applied.
                .clientSecret("{noop}demo-secret")

                .redirectUri("http://localhost:8080/auth")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantTypePassword.GRANT_PASSWORD)
                .tokenSettings(
                        TokenSettings.builder()
                                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                                .accessTokenTimeToLive(Duration.ofMinutes(300))
                                .refreshTokenTimeToLive(Duration.ofMinutes(600))
                                .authorizationCodeTimeToLive(Duration.ofMinutes(20))
                                .reuseRefreshTokens(false)
                                .build()
                )
                .build();

        RegisteredClient adminClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .id("9ac8b0c7-15c3-4d78-8ed5-02a8a5e1a253")
                .clientName("Admin client")
                .clientId("admin-client")

                // {noop} means "no operation," i.e., a raw password without any encoding applied.
                .clientSecret("{noop}admin-secret")

                .redirectUri("http://localhost:8080/auth")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantTypePassword.GRANT_PASSWORD)
                .tokenSettings(
                        TokenSettings.builder()
                                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                                .accessTokenTimeToLive(Duration.ofMinutes(300))
                                .refreshTokenTimeToLive(Duration.ofMinutes(600))
                                .authorizationCodeTimeToLive(Duration.ofMinutes(20))
                                .reuseRefreshTokens(false)
                                .build()
                )
                .build();

        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        if (registeredClientRepository.findByClientId(demoClient.getClientId()) == null) {
            registeredClientRepository.save(demoClient);
        }
        if (registeredClientRepository.findByClientId(adminClient.getClientId()) == null) {
            registeredClientRepository.save(adminClient);
        }
        return registeredClientRepository;

        //return new InMemoryRegisteredClientRepository(demoClient);
    }


}
