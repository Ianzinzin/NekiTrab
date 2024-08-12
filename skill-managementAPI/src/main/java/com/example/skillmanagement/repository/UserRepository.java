package com.example.skillmanagement.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.skillmanagement.entity.User;
import org.springframework.security.core.userdetails.UserDetails;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByLogin(String login);
}
