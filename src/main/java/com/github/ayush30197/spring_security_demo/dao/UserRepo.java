package com.github.ayush30197.spring_security_demo.dao;

import com.github.ayush30197.spring_security_demo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Integer> {
    User findByUsername(String username);
}
