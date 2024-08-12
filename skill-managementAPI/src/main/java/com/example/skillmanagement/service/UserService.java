package com.example.skillmanagement.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.skillmanagement.ENUM.UserRole;
import com.example.skillmanagement.dto.RegisterRequest;
import com.example.skillmanagement.dto.UserDTO;
import com.example.skillmanagement.entity.User;
import com.example.skillmanagement.repository.UserRepository;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public UserDTO registerNewUser(RegisterRequest registerRequest) {

        if (userRepository.findByLogin(registerRequest.getUsername()) != null) {
            throw new RuntimeException("User already exists");
        }


        UserRole userRole;
        try {
            userRole = UserRole.valueOf(registerRequest.getRole().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid role: " + registerRequest.getRole());
        }


        User newUser = new User(
            registerRequest.getUsername(),
            passwordEncoder.encode(registerRequest.getPassword()),
            userRole 

        );


        userRepository.save(newUser);


        UserDTO userDTO = new UserDTO(newUser.getId(), newUser.getLogin());

        return userDTO;
    }
}
