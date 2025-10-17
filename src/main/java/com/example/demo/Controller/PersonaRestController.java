package com.example.demo.controller;


import com.example.demo.model.Persona;
import com.example.demo.service.PersonaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/persona/")
public class PersonaRestController {
    private PersonaService personaService;
    @Autowired
    public PersonaRestController(PersonaService personaService) {
        this.personaService = personaService;
    }

    @PostMapping (value = "add", headers = "Accept=application/json")
    public void addperson (@RequestBody Persona persona) {
        personaService.addperson(persona);
    }

    @GetMapping (value = "listar", headers = "Accept=application/json")
    public List<Persona> personaList(){
        return personaService.listarpersona();
    }
    @GetMapping (value = "listarporid/{idPersona}", headers = "Accept=application/json")
    public Optional<Persona> buscarPorId(@PathVariable Long idPersona) {
        return personaService.buscarPorId(idPersona);
    }

    @DeleteMapping(value = "actualizar", headers = "Accept=application/json")
    public void actualizarPersona(@RequestBody Persona persona) {
        personaService.actualizarPersona(persona);
    }

    @GetMapping(value = "eliminar/{idPersona}", headers = "Accept=application/json")
    public void eliminarPersona(@PathVariable Long idPersona) {
        personaService.eliminarPersona(idPersona);
    }

    @GetMapping (value = "buscarporemail(email)")
    public List<Persona>  buscarporemail(@PathVariable String email){
        return personaService.buscarporemail(email);
    }

    @GetMapping(value = "buscarpornombre(nombre)")
    public List<Persona> buscarpornommre(@PathVariable String nombre){
        return personaService.buscarpornombre(nombre);
    }



}
