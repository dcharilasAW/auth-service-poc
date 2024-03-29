package com.demosso.authorizationserver.security;

import com.demosso.authorizationserver.domain.User;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;


public class CustomUserDetails implements UserDetails {
    @JsonProperty("password")
    private String password;

    @JsonProperty("username")
    private final String username;

    @JsonProperty("clientId")
    private final String clientId;

    @JsonProperty("authorities")
    private final Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetails(String username, String clientId, Collection<? extends GrantedAuthority> authorities) {
        this.username = username;
        this.authorities = authorities;
        this.clientId = clientId;
    }

    public CustomUserDetails(String username, String clientId, String password, Collection<String> authorities) {
        this.username = username;
        this.password = password;
        this.clientId = clientId;
        this.authorities = authorities.stream()
            .map(authority -> new SimpleGrantedAuthority(authority))
            .collect(Collectors.toList());
    }

    public CustomUserDetails(User user) {
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.clientId = user.getClientId();
        this.authorities = user.getRoles().stream()
            .flatMap(role -> role.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getName()))
            )
            .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public String getClientId() {
        return clientId;
    }
}