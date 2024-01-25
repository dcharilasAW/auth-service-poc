package com.demosso.authorizationserver.model;

import lombok.Data;

@Data
public class RegistrationRequest {

    private String username;
    private String password;
    private String clientId;
}
