package com.example.skillmanagement.dto;

import com.example.skillmanagement.ENUM.UserRole;

public record RegisterDTO(String login, String password, UserRole role) {
}