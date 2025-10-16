package com.example.demo.repository;

import com.example.demo.model.Sala;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Sala_Repositorio extends JpaRepository<Sala, Long> {

}
