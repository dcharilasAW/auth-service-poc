package com.demosso.authorizationserver.service.impl;

import com.demosso.authorizationserver.domain.User;
import com.demosso.authorizationserver.security.CustomUserDetails;
import com.demosso.authorizationserver.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserService userService;

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
}
