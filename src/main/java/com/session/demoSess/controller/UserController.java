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

        System.out.println("All authorities: " + authentication.getAuthorities());

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("username", authentication.getName());
        userInfo.put("authorities", authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .collect(java.util.stream.Collectors.toList()));
        userInfo.put("isAuthenticated", authentication.isAuthenticated());
        return ResponseEntity.ok(userInfo);
    }


    // Neue Methode zum Hinzufügen einer Rolle zu einem Benutzer
    @PostMapping("/users/{username}/roles")
    public ResponseEntity<?> addRoleToUser(@PathVariable String username, @RequestBody Map<String, String> roleRequest) {
        try {
            String roleName = roleRequest.get("role");
            if (roleName == null || roleName.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Role name is required"));
            }
            
            // Prüfen Sie, ob der Rollenname das Präfix 'ROLE_' hat
            if (!roleName.startsWith("ROLE_")) {
                roleName = "ROLE_" + roleName;
            }
            
            User user = userService.addRoleToUser(username, roleName);
            return ResponseEntity.ok(Map.of(
                "message", "Role added successfully",
                "username", user.getUsername(),
                "roles", user.getRoles()
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // Methode zum Entfernen einer Rolle von einem Benutzer
    @DeleteMapping("/users/{username}/roles/{role}")
    public ResponseEntity<?> removeRoleFromUser(@PathVariable String username, @PathVariable String role) {
        try {
            // Prüfen Sie, ob der Rollenname das Präfix 'ROLE_' hat
            if (!role.startsWith("ROLE_")) {
                role = "ROLE_" + role;
            }
            
            User user = userService.removeRoleFromUser(username, role);
            return ResponseEntity.ok(Map.of(
                "message", "Role removed successfully",
                "username", user.getUsername(),
                "roles", user.getRoles()
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
