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

public class Persona {
    @Id
    @GeneratedValue (strategy = GenerationType.IDENTITY)
    @Column (name = "id_persona")
    private Long idPersona;
    private String nombre;
    private String email;

    @ManyToOne
    @JoinColumn(name = "rol_name")
    private Rol rol;
    public void setRol(Rol rol) {
        this.rol = rol;
    }


}
