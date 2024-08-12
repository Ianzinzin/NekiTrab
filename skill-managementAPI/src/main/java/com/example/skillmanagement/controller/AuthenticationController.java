package com.example.skillmanagement.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.skillmanagement.dto.AuthenticationDTO;
import com.example.skillmanagement.dto.LoginResponseDTO;
import com.example.skillmanagement.dto.RegisterDTO;
import com.example.skillmanagement.entity.User;
import com.example.skillmanagement.repository.UserRepository;
import com.example.skillmanagement.service.TokenService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("auth")
public class AuthenticationController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository repository;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody @Valid AuthenticationDTO data) {
        // Encontrar o usuário pelo login
        User user = repository.findByLogin(data.login());

        // Verificar se o usuário existe e se a senha é válida
        if (user == null || !passwordEncoder.matches(data.password(), user.getPassword())) {
            return ResponseEntity.status(401).build(); // Unauthorized
        }

        // Gerar o token
        String token = tokenService.generateToken(user);

        // Retornar o token no corpo da resposta
        return ResponseEntity.ok(new LoginResponseDTO(token));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterDTO data) {
        // Verificar se o login já existe
        if (repository.findByLogin(data.login()) != null) {
            return ResponseEntity.badRequest().build(); // Bad Request
        }

        // Criptografar a senha e salvar o novo usuário
        String encryptedPassword = passwordEncoder.encode(data.password());
        User newUser = new User(data.login(), encryptedPassword, data.role());
        repository.save(newUser);

        return ResponseEntity.ok().build();
    }
}
