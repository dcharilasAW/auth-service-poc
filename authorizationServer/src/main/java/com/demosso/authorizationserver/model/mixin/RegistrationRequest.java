package com.demosso.authorizationserver.model.mixin;

import lombok.Data;

@Data
public class RegistrationRequest {

    private String username;
    private String password;
    private String clientId;
}
