package com.example.demo.Conf;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SegurityConf {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/error").permitAll()
                .requestMatchers("/api/persona/add", "/api/persona/actualizar", "/api/persona/eliminar/**").hasRole("ADMIN")
                .requestMatchers("/api/persona/listar", "/api/persona/listarporid/**").hasAnyRole("ADMIN", "USER")
                .requestMatchers("/api/articulo/add", "/api/articulo/actualizar", "/api/articulo/eliminar/**").hasRole("ADMIN")
                .requestMatchers("/api/articulo/listar", "/api/articulo/listar/**", "/api/articulo/buscarpornombre/**").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/api/salas/crear", "/api/salas/borrar/**").hasRole("ADMIN")
                .requestMatchers("/api/salas/listar", "/api/salas/buscar/**").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/api/reservas/crear", "/api/reservas/listar").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated()
            )
            // ✅ Usa sesiones en memoria (no JDBC, no JWT)
            .formLogin(form -> form
                .defaultSuccessUrl("/api/reservas/listar", true)
                .permitAll()
            )
            .logout(logout -> logout.permitAll())
            .httpBasic(b -> b.disable());

        return http.build();
    }
}
