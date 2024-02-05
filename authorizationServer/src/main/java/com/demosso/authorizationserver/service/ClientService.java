package com.demosso.authorizationserver.service;


import com.demosso.authorizationserver.constant.AuthProviderEnum;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public interface ClientService {
	RegisteredClient getByClientId(String clientId);

	AuthProviderEnum getClientTokenProvider(String clientId);

}