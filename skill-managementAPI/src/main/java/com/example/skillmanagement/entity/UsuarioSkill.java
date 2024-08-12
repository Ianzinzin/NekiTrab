package com.example.skillmanagement.entity;

import jakarta.persistence.*;

@Entity
public class UsuarioSkill {

    @EmbeddedId
    private UsuarioSkillId id = new UsuarioSkillId();

    public UsuarioSkill(User user, Skill skill) {
        this.id.setUser(user);
        this.id.setSkill(skill);
    }

    public UsuarioSkill() {
        // Construtor padrão
    }

    public UsuarioSkillId getId() {
        return id;
    }

    public void setId(UsuarioSkillId id) {
        this.id = id;
    }

    @Transient
    public User getUser() {
        return id.getUser();
    }

    @Transient
    public Skill getSkill() {
        return id.getSkill();
    }
}
