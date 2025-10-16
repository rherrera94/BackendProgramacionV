package com.example.demo.service;

import com.example.demo.model.Sala;
import com.example.demo.repository.Sala_Repositorio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


@Service
public class SalaService {

    private final  Sala_Repositorio sala_Repositorio;

    @Autowired
    public SalaService(Sala_Repositorio sala_Repositorio) {
        this.sala_Repositorio = sala_Repositorio;
    }

    public List<Sala> obtenerTodasLasSalas(){
        return sala_Repositorio.findAll();
    }

    public Optional<Sala> obtenerSalaPorId(Long id){
        return sala_Repositorio.findById(id);
    }

    public Sala guardarSala(Sala sala){
        return sala_Repositorio.save(sala);
    }

    public void borrarSala(Long id){
        sala_Repositorio.deleteById(id);
    }
}
