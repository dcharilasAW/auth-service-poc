package com.demosso.authorizationserver.repository;

import com.demosso.authorizationserver.domain.TokenProvider;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientProviderRepository extends CrudRepository<TokenProvider, String> {
	TokenProvider findByClientId(String clientId);

}