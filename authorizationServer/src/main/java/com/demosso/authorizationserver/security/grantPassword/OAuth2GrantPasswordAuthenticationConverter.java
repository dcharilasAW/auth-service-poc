package com.demosso.authorizationserver.security.grantPassword;

import com.demosso.authorizationserver.security.CustomUserDetails;
import com.demosso.authorizationserver.service.ClientService;
import com.demosso.authorizationserver.service.impl.CustomUserDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static com.demosso.authorizationserver.security.grantPassword.AuthorizationGrantTypePassword.GRANT_PASSWORD;

@Component
public class OAuth2GrantPasswordAuthenticationConverter implements AuthenticationConverter {

    private ClientService clientService;
    private CustomUserDetailsService userDetailsService;

    public OAuth2GrantPasswordAuthenticationConverter(ClientService clientService, CustomUserDetailsService userDetailsService) {
        this.clientService = clientService;
        this.userDetailsService = userDetailsService;
    }

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);

        if (!GRANT_PASSWORD.getValue().equals(grantType)) {
            return null;
        }

        MultiValueMap<String, String> parameters = getParameters(request);

        // scope (OPTIONAL)
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope)
            && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1
        ) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        // username (REQUIRED)
        String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
        if (!StringUtils.hasText(username)
            || parameters.get(OAuth2ParameterNames.USERNAME).size() != 1
        ) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        // password (REQUIRED)
        String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
        if (!StringUtils.hasText(password)
            || parameters.get(OAuth2ParameterNames.PASSWORD).size() != 1
        ) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(
                Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        Map<String, Object> additionalParameters = parameters.entrySet().stream()
            .filter(entry ->
                !OAuth2ParameterNames.GRANT_TYPE.equals(entry.getKey())
                    && !OAuth2ParameterNames.SCOPE.equals(entry.getKey())
                    && !OAuth2ParameterNames.PASSWORD.equals(entry.getKey())
                    && !OAuth2ParameterNames.USERNAME.equals(entry.getKey())
            )
            .collect(Collectors.toMap(entry -> entry.getKey(), entry -> entry.getValue().get(0)));

        // get registered client object
        //TODO handle case where not found
        RegisteredClient registeredClient = clientService.getByClientId(clientId);

        //Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        //TODO there has to be a better way to do this.
        //TODO below code is just to avoid getting principal from SecurityContextHolder, as each
        // user has its own client.

        // construct custom principal
        Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());

        // construct user details
        UserDetails user = null;
        try {
            user = userDetailsService.loadUserByUsernameAndClient(username,registeredClient.getId());
        } catch (UsernameNotFoundException e) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }
        CustomUserDetails userDetails = new CustomUserDetails(username, registeredClient.getClientId(), user.getAuthorities());

        try {
            FieldUtils.writeField(clientPrincipal, "details", userDetails, true);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }

        return new GrantPasswordAuthenticationToken(
            clientPrincipal, username, password, registeredClient.getId(), requestedScopes, additionalParameters
        );
    }

    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            if (values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }
}