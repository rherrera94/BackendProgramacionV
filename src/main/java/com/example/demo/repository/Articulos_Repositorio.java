package com.example.demo.repository;

import com.example.demo.model.Articulos;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository

public interface Articulos_Repositorio extends JpaRepository<Articulos, Long> {
    Articulos findByNombre(String nombre);

}

