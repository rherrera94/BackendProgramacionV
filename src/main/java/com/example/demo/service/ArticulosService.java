package com.example.demo.service;

import com.example.demo.model.Articulos;
import com.example.demo.repository.Articulos_Repositorio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ArticulosService {
    private final Articulos_Repositorio articulos_repositorio;

    @Autowired

    public ArticulosService(Articulos_Repositorio articulos_repositorio) {
        this.articulos_repositorio = articulos_repositorio;
    }

    public List<Articulos> listarArticulos() {
        return articulos_repositorio.findAll();
    }

    public Optional<Articulos> buscarPorId (Long idArticulo) {
        return articulos_repositorio.findById(idArticulo);
    }

    public void addArticulo(Articulos articulo) {
        articulos_repositorio.save(articulo);
    }

    public void updateArticulo(Articulos articulo) {
        articulos_repositorio.save(articulo);
    }

    public void delateArticulo(Long idArticulo) {
        articulos_repositorio.deleteById(idArticulo);
    }

    public Articulos buscarPorNombre (String nombre) {
        return articulos_repositorio.findByNombre(nombre);
    }


}
