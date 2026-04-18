package com.example.projecto_html.controller;

import com.example.projecto_html.entitiy.usuario;
import com.example.projecto_html.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.Optional;
import java.util.Map;
import java.util.HashMap;

@RestController
@RequestMapping("/api/usuarios")
@CrossOrigin(origins = "*")
public class UsuarioController {
    @Autowired
    private UsuarioRepository usuarioRepository; // Aquí llamamos a tu repositorio

    @PostMapping("/registro")
    public String registrarUsuario(@RequestBody usuario nuevoUsuario) {
        usuarioRepository.save(nuevoUsuario);
        return "¡Usuario guardado con éxito!";
    }

    @PostMapping("/login")
    public Map<String, String> loginUsuario(@RequestBody usuario credenciales) {
        Map<String, String> respuesta = new HashMap<>();
        Optional<usuario> usuarioEncontrado = usuarioRepository.findByUsername(credenciales.getUsername());
        if (usuarioEncontrado.isEmpty()) {
            respuesta.put("mensaje", "Error: Contraseña o usuario incorrectos");
            return respuesta;
        }
        usuario usuarioReal = usuarioEncontrado.get();
        if (usuarioReal.getPassword().equals(credenciales.getPassword()) && !usuarioEncontrado.isEmpty()) {
            respuesta.put("mensaje", "Exito: Usuario logueado correctamente");
            respuesta.put("email", usuarioReal.getEmail());
            return respuesta;
        } else {
            respuesta.put("mensaje", "Error: Contraseña o usuario incorrectos");
            return respuesta;
        }
    }
}
