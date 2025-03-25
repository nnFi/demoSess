package com.session.demoSess.initializer;

import com.session.demoSess.entity.Role;
import com.session.demoSess.entity.User;
import com.session.demoSess.repository.RoleRepository;
import com.session.demoSess.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    @SuppressWarnings("unused")
    public void run(String... args) throws Exception {
        // First create all roles
        Role userRole = createRoleIfNotFound("ROLE_USER");
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN");
        Role moderatorRole = createRoleIfNotFound("ROLE_MODERATOR");

        // Then create the admin user if it doesn't exist
        if (!userRepository.findByUsername("admin").isPresent()) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin"));
            admin.setEnabled(true);
            
            // Directly use the role objects we just created
            admin.setRoles(new HashSet<>(Arrays.asList(adminRole, userRole)));
            
            userRepository.save(admin);
            System.out.println("Admin user created: admin/admin");
        } else {
            // Ensure existing admin has the admin role
            userRepository.findByUsername("admin").ifPresent(admin -> {
                if (admin.getRoles() == null || !admin.getRoles().stream().anyMatch(r -> r.getName().equals("ROLE_ADMIN"))) {
                    Set<Role> roles = admin.getRoles() != null ? admin.getRoles() : new HashSet<>();
                    roles.add(adminRole);
                    roles.add(userRole);
                    admin.setRoles(roles);
                    userRepository.save(admin);
                    System.out.println("Updated admin user with proper roles");
                } else {
                    System.out.println("Admin user already has proper roles");
                }
            });
        }
    }

    private Role createRoleIfNotFound(String name) {
        return roleRepository.findByName(name)
                .orElseGet(() -> {
                    Role role = new Role(name);
                    roleRepository.save(role);
                    System.out.println("Created role: " + name);
                    return role;
                });
    }
}
