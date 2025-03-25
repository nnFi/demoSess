package com.session.demoSess.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import com.session.demoSess.entity.User;
import com.session.demoSess.service.UserService;

import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        try {
            user.setEnabled(true);
            User registeredUser = userService.registerUser(user);
            return ResponseEntity.ok(registeredUser);
        } catch (Exception e) {
            Map<String, String> response = new HashMap<>();
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginRequest, HttpServletRequest request) {
        try {
            String username = loginRequest.get("username");
            String password = loginRequest.get("password");
            
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
            
            SecurityContextHolder.getContext().setAuthentication(authentication);

            request.getSession().setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, 
                SecurityContextHolder.getContext()
            );
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Login successful");
            response.put("username", username);
            
            return ResponseEntity.ok(response);
        } catch (AuthenticationException e) {
            Map<String, String> response = new HashMap<>();
            response.put("status", "error");
            response.put("message", "Invalid username or password");
            return ResponseEntity.status(401).body(response);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        try {
            // Holen Sie sich die aktuelle Authentifizierung, falls vorhanden
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            
            if (auth != null) {
                // Session invalidieren und den Kontext löschen
                request.getSession().invalidate();
                SecurityContextHolder.clearContext();
            }
            
            Map<String, String> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Logout successful");
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> response = new HashMap<>();
            response.put("status", "error");
            response.put("message", "Logout failed: " + e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    @GetMapping("/user/current")
    public ResponseEntity<?> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("username", authentication.getName());
        userInfo.put("authorities", authentication.getAuthorities());
        userInfo.put("isAuthenticated", authentication.isAuthenticated());
        return ResponseEntity.ok(userInfo);
    }

    // For testing authentication with a simple endpoint
    @GetMapping("/test-auth")
    public ResponseEntity<?> testAuth() {
        return ResponseEntity.ok(Map.of("message", "You are authenticated!"));
    }
}

