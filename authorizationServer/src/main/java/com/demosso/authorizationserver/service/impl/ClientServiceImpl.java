package com.demosso.authorizationserver.service.impl;

import com.demosso.authorizationserver.service.ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class ClientServiceImpl implements ClientService {

	private final RegisteredClientRepository repository;

	@Override
	public RegisteredClient getByClientId(String clientId) {
		return repository.findByClientId(clientId);
	}
}
