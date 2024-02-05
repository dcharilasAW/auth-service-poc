package com.demosso.authorizationserver.service;

import com.demosso.authorizationserver.model.auth0.TokenResponse;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;

@Service
public class Auth0IntegrationServiceImpl {

    @Value(value = "${com.auth0.domain}")
    private String domain;

    @Value(value = "${com.auth0.clientId}")
    private String clientId;

    @Value(value = "${com.auth0.clientSecret}")
    private String clientSecret;

    @Value(value = "${com.auth0.managementApi.clientId}")
    private String managementApiClientId;

    @Value(value = "${com.auth0.managementApi.clientSecret}")
    private String managementApiClientSecret;

    @Value(value = "${com.auth0.managementApi.grantType}")
    private String grantType;

    public TokenResponse getApiToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        JSONObject requestBody = new JSONObject();
        requestBody.put("client_id", clientId);
        requestBody.put("client_secret", clientSecret);
        requestBody.put("audience", "http://localhost:8090");
        //TODO if user requests a scope that is not assigned as permission then access is denied to everything

        requestBody.put("grant_type", grantType);

        HttpEntity<String> request = new HttpEntity<String>(requestBody.toString(), headers);

        RestTemplate restTemplate = new RestTemplate();
        TokenResponse result = restTemplate.postForObject("https://" + domain +"/oauth/token", request, TokenResponse.class);
        return result;
    }

    public String getManagementApiToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        JSONObject requestBody = new JSONObject();
        requestBody.put("client_id", managementApiClientId);
        requestBody.put("client_secret", managementApiClientSecret);
        requestBody.put("audience", "https://" + domain +"/api/v2/");
        requestBody.put("scope", "read:users read:userByEmail");
        //TODO if user requests a scope that is not assigned as permission then access is denied to everything

        requestBody.put("grant_type", grantType);

        HttpEntity<String> request = new HttpEntity<String>(requestBody.toString(), headers);

        RestTemplate restTemplate = new RestTemplate();
        HashMap<String, String> result = restTemplate.postForObject("https://" + domain +"/oauth/token", request, HashMap.class);

        return result.get("access_token");
    }

}
