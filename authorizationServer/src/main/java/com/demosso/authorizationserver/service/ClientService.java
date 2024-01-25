package com.demosso.authorizationserver.service;


import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public interface ClientService {
	RegisteredClient getByClientId(String clientId);

}