package com.example.demo.repository;

import com.example.demo.model.Rol;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Rol_Repositorio extends JpaRepository<Rol, Long> {

    Rol findByNombre(String nombre);

}
