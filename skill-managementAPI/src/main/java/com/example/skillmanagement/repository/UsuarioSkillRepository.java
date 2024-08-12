package com.example.skillmanagement.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.skillmanagement.entity.UsuarioSkill;
import com.example.skillmanagement.entity.UsuarioSkillId;

@Repository
public interface UsuarioSkillRepository extends JpaRepository<UsuarioSkill, UsuarioSkillId> {
    Optional<UsuarioSkill> findById(UsuarioSkillId id);
}
