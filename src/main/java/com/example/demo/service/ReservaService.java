package com.example.demo.service;

import com.example.demo.model.Reserva;
import com.example.demo.repository.Reserva_Repositorio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ReservaService {

    private final Reserva_Repositorio reservaRepository;

    @Autowired
    public ReservaService(Reserva_Repositorio reservaRepository) {
        this.reservaRepository = reservaRepository;
    }

    // Método para obtener todas las reservas
    public List<Reserva> obtenerTodasLasReservas() {
        return reservaRepository.findAll();
    }

    // Método para crear una reserva
    public Reserva crearReserva(Reserva reserva) {
        // --- ¡AQUÍ IRÍA LA LÓGICA IMPORTANTE! ---
        // Por ejemplo: antes de guardar, deberías verificar que la sala o
        // el artículo no estén ya reservados en ese horario.
        // Por ahora, simplemente la guardamos.
        return reservaRepository.save(reserva);
    }
}
