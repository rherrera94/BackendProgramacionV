package com.example.demo.Conf;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager; //maneja autenticacion
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;//sirve para validar las credenciales
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; //se utilizara para hashear las contraseñas
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain; //filtros de seguridad y reglas de autorización

import java.util.stream.Collectors;
/*
    Dentro de esta clase vamos a realizar ciertas configuraciones generales en
    lo que respecta a la seguridad del sistema. Aca vamos a configurar las reglas
    de autenticacion y autorizacion. Vamos a informar a que partes de nuestra api 
    los diferentes tipos de usuarios pueden o no realizar peticiones. Realizaremos 
    un acceso basado en roles y según el rol es a la ruta que los usuarios podran 
    o no acceder.
*/
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

/**
 * En esta función encontraremos las reglas de autorización de nuestra API. Autorizamos las peticiones
 * a la API según el rol que tiene cada uno de los usuarios (por ejemplo administrador, usuario común).
 *      - .permitall()-> Acceden todos los usuarios, no hace falta estar logueado.
 *      - .hasRole()-> Permite el acceso solo al tipo de usuario nombrado.
 *      - .hasAnyRole()->Permite el acceso a los tipos de usuario que se nombran.
 *      - .anyRequest().authenticated()-> todo lo que no esta listado en las rutas, para poder acceder habra que estar autenticado.
 */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/login", "/error", "/auth/generate").permitAll()
                        .requestMatchers("/api/articulo/add", "/api/articulo/actualizar", "/api/articulo/eliminar/**","/api/persona/add", "/api/persona/actualizar", "/api/persona/eliminar/**","/api/usuario/add","/api/usuario/listar").hasRole("ADMIN")
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
