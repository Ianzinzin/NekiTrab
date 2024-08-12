package com.example.skillmanagement.dto;

public class RegisterRequest {
    
    private String username;
    private String password;
    private String role; // Adiciona o campo 'role' se ele não existir

    // Construtores, getters, e setters
    
    public RegisterRequest() {}

    public RegisterRequest(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {  // Adiciona o método getRole se ele não existir
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
