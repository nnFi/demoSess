package com.session.demoSess.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.session.demoSess.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}