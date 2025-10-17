package com.example.demo.controller;

import com.example.demo.model.Reserva;
import com.example.demo.service.ReservaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/reservas")
public class ReservaRestController {

    private final ReservaService reservaService;

    @Autowired
    public ReservaRestController(ReservaService reservaService) {
        this.reservaService = reservaService;
    }

    // Endpoint para listar todas las reservas
    // URL: GET http://localhost:8080/api/reservas/listar
    @GetMapping("/listar")
    public List<Reserva> listarTodas(){
        return reservaService.obtenerTodasLasReservas();
    }


    // Endpoint para crear una nueva reserva
    // URL: POST http://localhost:8080/api/reservas/crear
    @PostMapping("/crear")
    public Reserva crearReserva(@RequestBody Reserva reserva){
        return reservaService.crearReserva(reserva);
    }
}
