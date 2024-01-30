package com.demosso.authorizationserver.security.usernamePassword;

import com.demosso.authorizationserver.service.ClientService;
import com.demosso.authorizationserver.service.impl.CustomUserDetailsService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

import java.security.Principal;

import static com.demosso.authorizationserver.security.grantPassword.AuthorizationGrantTypePassword.GRANT_PASSWORD;


public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final Log logger = LogFactory.getLog(getClass());
    private final OAuth2AuthorizationService authorizationService;
    private final CustomUserDetailsService userDetailsService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final PasswordEncoder passwordEncoder;

    private final ClientService clientService;

    public UsernamePasswordAuthenticationProvider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            CustomUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder, ClientService clientService
    ) {
        this.clientService = clientService;
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        Assert.notNull(userDetailsService, "userDetailsService cannot be null");
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken customPasswordAuthenticationToken =
            (UsernamePasswordAuthenticationToken) authentication;


        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();
        //TODO get client somehow, for now hardcoded
        String clientId = "demo-client";
        RegisteredClient registeredClient = clientService.getByClientId(clientId);

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }

        // Ensure the client is configured to use this authorization grant type
        if (registeredClient == null || !registeredClient.getAuthorizationGrantTypes().contains(GRANT_PASSWORD)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved authorization with username and password");
        }



        UserDetails user = null;
        try {
            user = userDetailsService.loadUserByUsernameAndClient(username,registeredClient.getId());
        } catch (UsernameNotFoundException e) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }

        if (!user.getUsername().equals(username)
            || !passwordEncoder.matches(password, user.getPassword())
        ) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }

        //TODO find a way to properly fill authorizationServerContext. If left empty token cannot be generated.
        AuthorizationServerSettings settings =  AuthorizationServerSettings.builder().build();
        AuthorizationServerContext authorizationServerContext =
                new AuthorizationServerContext(
                ) {
                    @Override
                    public String getIssuer() {
                        return null;
                    }

                    @Override
                    public AuthorizationServerSettings getAuthorizationServerSettings() {
                        return null;
                    }
                };

        AuthorizationServerContextHolder.setContext(authorizationServerContext);

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(authentication)
            .authorizationServerContext(
                // Issuer contains here
                AuthorizationServerContextHolder.getContext()
            )
            .authorizedScopes(registeredClient.getScopes())
            .authorizationGrantType(GRANT_PASSWORD)
            .authorizationGrant(customPasswordAuthenticationToken);

        // Generate the access token
        OAuth2TokenContext tokenContext = tokenContextBuilder
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .build();

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);

        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Generated access token");
        }

        // ----- Access token -----
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(),
            generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(),
            tokenContext.getAuthorizedScopes()
        );

        // Initialize the OAuth2Authorization
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .attribute(Principal.class.getName(), authentication)
            .principalName(registeredClient.getClientId())
            .authorizationGrantType(GRANT_PASSWORD)
            .authorizedScopes(registeredClient.getScopes());

        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) ->
                metadata.put(
                    OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                    ((ClaimAccessor) generatedAccessToken).getClaims()
                )
            );
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        // ----- Refresh token -----
        OAuth2RefreshToken refreshToken = null;

        //if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
        //    && !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)
        //) {
            tokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .build();

            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);

            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        //}

        OAuth2Authorization authorization = authorizationBuilder.build();

        this.authorizationService.save(authorization);

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Saved authorization");
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Authenticated token request");
        }

        return new OAuth2AccessTokenAuthenticationToken(
            registeredClient, authentication, accessToken, refreshToken
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
