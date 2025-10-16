package com.example.demo.model;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="salas")

public class Sala {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idSala;

    @Column(name = "nombre", nullable = false)
    private String nombre;

    @Column(name = "capacidad", nullable = false)
    private int capacidad;

}
