package com.example.projecto_html.controller;

import com.example.projecto_html.entitiy.usuario;
import com.example.projecto_html.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.Optional;
import java.util.Map;
import java.util.HashMap;
import org.mindrot.jbcrypt.BCrypt;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

@RestController
@RequestMapping("/api/usuarios")
@CrossOrigin(origins = "*")
public class UsuarioController {
    @Autowired
    private UsuarioRepository usuarioRepository; // Aquí llamamos a tu repositorio

    @PostMapping("/registro")
    public String registrarUsuario(@RequestBody usuario nuevoUsuario) {
        Optional<usuario> usuarioExistente = usuarioRepository.findByUsername(nuevoUsuario.getUsername());
        if (!usuarioExistente.isEmpty()) {
            return "Error: Usuario ya ocupado";
        }
        Optional<usuario> emailExistente = usuarioRepository.findByEmail(nuevoUsuario.getEmail());
        if (!emailExistente.isEmpty()) {
            return "Error: Correo ya registrado";
        }
        String contrasenaEncriptada = BCrypt.hashpw(nuevoUsuario.getPassword(), BCrypt.gensalt());
        nuevoUsuario.setPassword(contrasenaEncriptada);
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
        if (BCrypt.checkpw(credenciales.getPassword(), usuarioReal.getPassword()) && !usuarioEncontrado.isEmpty()) {
            Algorithm algorithm = Algorithm.HMAC256("miSecretoAbsoluto");
            String token = JWT.create().withIssuer("projecto_html_auth")
                    .withClaim("username", usuarioReal.getUsername()).sign(algorithm);
            respuesta.put("mensaje", "Exito: Usuario logueado correctamente");
            respuesta.put("email", usuarioReal.getEmail());
            respuesta.put("token", token);
            return respuesta;
        } else {
            respuesta.put("mensaje", "Error: Contraseña o usuario incorrectos");
            return respuesta;
        }
    }
}
