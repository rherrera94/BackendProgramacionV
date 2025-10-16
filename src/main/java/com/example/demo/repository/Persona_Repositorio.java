package com.example.demo.repository;

import com.example.demo.model.Persona;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;


//encontrar equis cosa
@Repository
public interface Persona_Repositorio extends JpaRepository <Persona, Long> {
    List<Persona> findByEmail(String email);
    List<Persona> findByNombre (String nombre);

}
