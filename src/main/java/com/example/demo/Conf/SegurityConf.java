package com.example.demo.Conf;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.stream.Collectors;

@Configuration
public class SegurityConf {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(com.example.demo.repository.UsuarioRepository usuarioRepository) {
        return username -> usuarioRepository.findByUsername(username)
                .map(usuario -> {
                    System.out.println("Usuario encontrado: " + usuario.getUsername());
                    System.out.println("Password almacenado: " + usuario.getPassword());

                    return new org.springframework.security.core.userdetails.User(
                            usuario.getUsername(),
                            usuario.getPassword(),
                            usuario.getRoles().stream()
                                    .map(rol -> new SimpleGrantedAuthority(rol.getNombre()))
                                    .collect(Collectors.toList())
                    );
                })
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(
            UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {

        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/login", "/error", "/auth/generate").permitAll()
                        .requestMatchers("/api/articulo/add", "/api/articulo/actualizar", "/api/articulo/eliminar/**","/api/persona/add", "/api/persona/actualizar", "/api/persona/eliminar/**","api/usuario/add","/api/usuario/listar").hasRole("ADMIN")
                        .requestMatchers("/api/persona/listar", "/api/persona/listarporid/**", "/api/articulo/listar/**", "/api/articulo/buscarpornombre/**", "/api/reservas/**")
                        .hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.permitAll());

        return http.build();
    }
}
