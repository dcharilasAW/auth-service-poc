package com.demosso.authorizationserver.configuration.client;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@ConfigurationProperties(prefix = "ctp.auth")
public class ClientsProperties {

    @NestedConfigurationProperty
    private final Map<String, Client> client = new HashMap<>();

    public Map<String, Client> getClient() {
        return client;
    }

    public static class Client {
        private String clientId;
        private String clientSecret;
        private String clientName;
        private Set<ClientAuthenticationMethod> clientAuthenticationMethods;
        private Set<AuthorizationGrantType> authorizationGrantTypes;
        private Set<String> scopes = new HashSet<>();
        @NestedConfigurationProperty
        private final Map<String, String> tokenSettings = new HashMap<>();

        public Map<String, String> getTokenSettings() {
            return tokenSettings;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getClientName() {
            return clientName;
        }

        public void setClientName(String clientName) {
            this.clientName = clientName;
        }

        public Set<ClientAuthenticationMethod> getClientAuthenticationMethods() {
            return clientAuthenticationMethods;
        }

        public void setClientAuthenticationMethods(Set<ClientAuthenticationMethod> clientAuthenticationMethods) {
            this.clientAuthenticationMethods = clientAuthenticationMethods;
        }

        public Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
            return authorizationGrantTypes;
        }

        public void setAuthorizationGrantTypes(Set<AuthorizationGrantType> authorizationGrantTypes) {
            this.authorizationGrantTypes = authorizationGrantTypes;
        }

        public Set<String> getScopes() {
            return scopes;
        }

        public void setScopes(Set<String> scopes) {
            this.scopes = scopes;
        }
    }
}