package com.demosso.authorizationserver.service;


import com.demosso.authorizationserver.domain.User;
import jakarta.mail.MessagingException;

import java.io.UnsupportedEncodingException;

public interface UserService {
	User getByUsername(String username);

    User getByUsernameAndClient(String username, String clientId);

    User save(User user);

    void generateOneTimePassword(User user) throws MessagingException, UnsupportedEncodingException;

    void clearOTP(User user);
}