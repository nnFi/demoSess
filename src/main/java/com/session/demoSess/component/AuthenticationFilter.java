package com.session.demoSess.component;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        // Log authentication details for debugging
        if (authentication != null) {
            logger.debug("Authentication in filter: " + authentication.getName() + 
                ", Authorities: " + authentication.getAuthorities() + 
                ", Authenticated: " + authentication.isAuthenticated());
        } else {
            logger.debug("No authentication found in SecurityContext");
        }
        
        filterChain.doFilter(request, response);
    }
}