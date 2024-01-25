package com.demosso.authorizationserver.security.grantPassword;


import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static com.demosso.authorizationserver.security.grantPassword.AuthorizationGrantTypePassword.GRANT_PASSWORD;

@Getter
public class GrantPasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private static final long serialVersionUID = 1L;
    private final String username;
    private final String password;

    private final String clientId;
    private final Set<String> scopes;

    public GrantPasswordAuthenticationToken(
        Authentication clientPrincipal,
        String username,
        String password,
        String clientId,
        @Nullable Set<String> scopes,
        @Nullable Map<String, Object> additionalParameters
    ) {
        super(GRANT_PASSWORD, clientPrincipal, additionalParameters);
        Assert.hasText(username, "username cannot be empty");
        Assert.hasText(password, "password cannot be empty");
        Assert.hasText(clientId, "client id cannot be empty");
        this.username = username;
        this.password = password;
        this.clientId = clientId;
        this.scopes = Collections.unmodifiableSet(
            scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }
}