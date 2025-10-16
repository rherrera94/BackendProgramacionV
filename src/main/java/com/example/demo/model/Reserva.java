package com.example.demo.model;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.time.LocalDateTime;

@Entity
@Table(name = "reservas")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

public class Reserva {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @ManyToOne
    @JoinColumn(name="id_persona", nullable = false)
    private Persona persona;

    @ManyToOne
    @JoinColumn(name="id_sala")
    private Sala sala;

    @ManyToOne
    @JoinColumn(name="id_articulo")
    private Articulos articulo;

    @Column(name = "fecha_hora_inicio", nullable = false)
    private LocalDateTime fechaHoraInicio;

    @Column(name="fecha_hora_fin", nullable = false)
    private LocalDateTime fechaHoraFin;

}
