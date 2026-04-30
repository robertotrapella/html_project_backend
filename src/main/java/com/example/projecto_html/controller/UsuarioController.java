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
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;

@RestController
@RequestMapping("/api/usuarios")
@CrossOrigin(origins = "*")
public class UsuarioController {
    @Autowired
    private UsuarioRepository usuarioRepository; // Aquí llamamos a tu repositorio

    @PostMapping("/registro")
    public Map<String, String> registrarUsuario(@RequestBody usuario nuevoUsuario) {
        Map<String, String> respuesta = new HashMap<>();
        Optional<usuario> usuarioExistente = usuarioRepository.findByUsername(nuevoUsuario.getUsername());
        if (!usuarioExistente.isEmpty()) {
            respuesta.put("mensaje", "Error: Usuario ya ocupado");
            return respuesta;
        }
        Optional<usuario> emailExistente = usuarioRepository.findByEmail(nuevoUsuario.getEmail());
        if (!emailExistente.isEmpty()) {
            respuesta.put("mensaje", "Error: Correo ya registrado");
            return respuesta;
        }
        Algorithm algorithm = Algorithm.HMAC256("miSecretoAbsoluto");
        String token = JWT.create().withIssuer("projecto_html_auth")
                .withClaim("username", nuevoUsuario.getUsername())
                .withClaim("email", nuevoUsuario.getEmail()).sign(algorithm);
        String contrasenaEncriptada = BCrypt.hashpw(nuevoUsuario.getPassword(), BCrypt.gensalt());
        nuevoUsuario.setPassword(contrasenaEncriptada);
        usuarioRepository.save(nuevoUsuario);
        respuesta.put("mensaje", "¡Usuario guardado con éxito!");
        respuesta.put("token", token);

        return respuesta;
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
                    .withClaim("username", usuarioReal.getUsername())
                    .withClaim("email", usuarioReal.getEmail()).sign(algorithm);
            respuesta.put("mensaje", "Exito: Usuario logueado correctamente");
            respuesta.put("email", usuarioReal.getEmail());
            respuesta.put("token", token);
            return respuesta;
        } else {
            respuesta.put("mensaje", "Error: Contraseña o usuario incorrectos");
            return respuesta;
        }
    }

    @GetMapping("/perfil")
    public Map<String, String> obtenerPerfil(
            @RequestHeader(value = "Authorization", required = false) String tokenHeader) {
        Map<String, String> respuesta = new HashMap<>();
        if (tokenHeader == null || !tokenHeader.startsWith("Bearer ")) {
            respuesta.put("error", "Error: Acceso denegado");
            return respuesta;
        }
        String token = tokenHeader.replace("Bearer ", "");
        try {
            Algorithm algorithm = Algorithm.HMAC256("miSecretoAbsoluto");
            JWTVerifier verifier = JWT.require(algorithm).withIssuer("projecto_html_auth").build();
            DecodedJWT jwt = verifier.verify(token);
            String username = jwt.getClaim("username").asString();
            respuesta.put("mensaje", "Acceso concedido" + username);
            return respuesta;
        } catch (JWTVerificationException exception) {
            respuesta.put("error", "Acceso denegado, Token invalido");
            return respuesta;
        }
    }
}
