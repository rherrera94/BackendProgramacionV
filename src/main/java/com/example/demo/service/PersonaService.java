package com.example.demo.service;


import com.example.demo.model.Persona;
import com.example.demo.repository.Persona_Repositorio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


@Service
public class PersonaService {


    private Persona_Repositorio persorepo;
    @Autowired

    public PersonaService(Persona_Repositorio persorepo) {
        this.persorepo = persorepo;
    }

    public void addperson (Persona persona) {
        persorepo.save(persona);
    }

    public List<Persona> listarpersona() {
        return persorepo.findAll();
    }

    public Optional<Persona> buscarPorId(Long idPersona) {
        return persorepo.findById(idPersona);
    }

    public void actualizarPersona (Persona persona) {
        persorepo.save(persona);
    }


    public void eliminarPersona(Long idPersona) {
        persorepo.deleteById(idPersona);
    }


    public List<Persona> buscarporemail (String email) {
        return persorepo.findByEmail(email);
    }

    public List<Persona> buscarpornombre (String nombre) {
        return persorepo.findByNombre(nombre);

    }




}

