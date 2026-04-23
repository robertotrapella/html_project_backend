package com.example.projecto_html.repository;

import com.example.projecto_html.entitiy.usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UsuarioRepository extends JpaRepository<usuario, Long> {
    Optional<usuario> findByUsername(String username);

    Optional<usuario> findByEmail(String email);
}
