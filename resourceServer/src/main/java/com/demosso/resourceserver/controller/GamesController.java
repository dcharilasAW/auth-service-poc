package com.demosso.resourceserver.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.Mapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GamesController {

    @PreAuthorize("hasAuthority('GAME_VIEW')")
    @GetMapping("/games")
    public String read() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "demo read string";
    }

    @PreAuthorize("hasAuthority('GAME_PLAY')")
    @PostMapping("/games/play")
    public String write() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "demo write string";
    }
}
