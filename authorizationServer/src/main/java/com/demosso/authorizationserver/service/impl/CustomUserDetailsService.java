package com.demosso.authorizationserver.service.impl;

import com.demosso.authorizationserver.domain.Role;
import com.demosso.authorizationserver.domain.User;
import com.demosso.authorizationserver.model.mixin.RegistrationRequest;
import com.demosso.authorizationserver.security.CustomUserDetails;
import com.demosso.authorizationserver.service.ClientService;
import com.demosso.authorizationserver.service.RoleService;
import com.demosso.authorizationserver.service.UserService;
import lombok.SneakyThrows;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

import java.util.Set;


@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserService userService;
    private final RoleService roleService;
    private final ClientService clientService;
    private final PasswordEncoder passwordEncoder;

    public CustomUserDetailsService(UserService userService, RoleService roleService, ClientService clientService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.roleService = roleService;
        this.clientService = clientService;
        this.passwordEncoder = passwordEncoder;
    }

    //TODO this should not be used, maybe replace UserDetailsService with CustomUserDetailsService
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.getByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("Unable to found user: " + username);
        }

        return new CustomUserDetails(user);
    }

    public UserDetails loadUserByUsernameAndClient(String username, String clientId) throws UsernameNotFoundException {
        User user = userService.getByUsernameAndClient(username,clientId);

        if (user == null) {
            throw new UsernameNotFoundException("Unable to found user: " + username);
        }

        return new CustomUserDetails(user);
    }

    @SneakyThrows
    public User registerUser(RegistrationRequest request) {

        //TODO add proper error handling
        RegisteredClient client = clientService.getByClientId(request.getClientId());

        //TODO add proper error handling
        if (userService.getByUsernameAndClient(request.getUsername(),client.getId()) != null) {
            throw new Exception("user already exists");
        }

        //TODO add some logic for roles
        Role defaultRole = request.getClientId().contains("admin") ?
                roleService.getByName("NORMAL_ADMIN") : roleService.getByName("USER");
        User user = User.builder()
                .active(true)
                .username(request.getUsername())
                //TODO add encryption
                //.password(passwordEncoder.encode(request.getPassword()))
                .password("{noop}" + request.getPassword())
                .clientId(client.getId())
                .roles(Set.of(defaultRole))
                .build();
        return userService.save(user);
    }


}
