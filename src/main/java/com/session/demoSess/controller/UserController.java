package com.session.demoSess.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserController {

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "Welcome, " + authentication.getName();
    }
}

