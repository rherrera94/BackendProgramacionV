package com.example.demo.Controller;

import com.example.demo.model.Sala;
import com.example.demo.service.SalaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/salas") // Todas las URLs de salas empezarán con esto
public class SalaRestController {

    private final SalaService salaService;

    @Autowired
    public SalaRestController(SalaService salaService) {
        this.salaService = salaService;
    }

    // Endpoint para listar todas las salas
    // URL: GET http://localhost:8080/api/salas/listar
    @GetMapping("/listar")
    public List<Sala> listarTodas() {
        return salaService.obtenerTodasLasSalas();
    }

    // Endpoint para buscar una sala por su ID
    // URL: GET http://localhost:8080/api/salas/buscar/1
    @GetMapping("/buscar/{id}")
    public Optional<Sala> buscarPorId(@PathVariable Long id) {
        return salaService.obtenerSalaPorId(id);
    }

    // Endpoint para crear una nueva sala
    // URL: POST http://localhost:8080/api/salas/crear
    @PostMapping("/crear")
    public Sala crearSala(@RequestBody Sala sala) {
        return salaService.guardarSala(sala);
    }

    // Endpoint para borrar una sala por su ID
    // URL: DELETE http://localhost:8080/api/salas/borrar/1
    @DeleteMapping("/borrar/{id}")
    public void borrarSala(@PathVariable Long id){
        salaService.borrarSala(id);
    }
}