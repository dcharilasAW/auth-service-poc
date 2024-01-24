package com.demosso.authorizationserver.service;


import com.demosso.authorizationserver.domain.User;

public interface UserService {
	User getByUsername(String username);

    User getByUsernameAndClient(String username, String clientId);

    User save(User user);
}