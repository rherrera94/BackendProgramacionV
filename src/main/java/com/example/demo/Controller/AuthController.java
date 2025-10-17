package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public Object login(@RequestParam String username,
                        @RequestParam String password,
                        HttpSession session) {
        try {
            // 🔐 Autentica el usuario con Spring Security
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            // ✅ Guarda la sesión en el contexto de seguridad
            SecurityContextHolder.getContext().setAuthentication(authentication);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            // 🟢 Devuelve el ID de sesión para que el front o Postman lo use como cookie
            return new LoginResponse("Sesión iniciada correctamente", session.getId());

        } catch (AuthenticationException e) {
            // 🔴 Si las credenciales no son válidas
            return new LoginResponse("Error: credenciales inválidas", null);
        }
    }

    // ✅ Endpoint opcional para cerrar sesión
    @PostMapping("/logout")
    public LoginResponse logout(HttpSession session) {
        session.invalidate();
        return new LoginResponse("Sesión cerrada correctamente", null);
    }
    @GetMapping("/generate")
    public String generatePassword() {
        org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder encoder =
                new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
        return encoder.encode("1234");
    }


    // 📦 Clase interna para la respuesta
    public record LoginResponse(String mensaje, String sessionId) {}
}
