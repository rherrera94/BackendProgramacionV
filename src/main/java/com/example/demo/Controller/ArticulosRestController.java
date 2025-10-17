package com.example.demo.controller;


import com.example.demo.model.Articulos;
import com.example.demo.service.ArticulosService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping ("/api/articulo")
public class ArticulosRestController {

    private final ArticulosService articulosService;

    @Autowired
    public ArticulosRestController(ArticulosService articulosService) {
        this.articulosService = articulosService;
    }

    @GetMapping (value = "listar")
    public List<Articulos> listarArticulos() {
        return articulosService.listarArticulos();
    }

    @GetMapping (value = "listar/{id}")
    public Optional<Articulos> listarArticulos(@PathVariable Long id) {
        return articulosService.buscarPorId(id);
    }

    @PostMapping (value = "add")
    public void addArticulo (@RequestBody Articulos articulo) {
        articulosService.addArticulo(articulo);
    }

    @PutMapping (value = "update")
    public void updateArticulo (@RequestBody Articulos articulo) {
        articulosService.updateArticulo(articulo);
    }

    @DeleteMapping (value = "delete/{id}")
    public void deleteArticulo (@PathVariable Long id) {
        articulosService.delateArticulo(id);
    }

    @GetMapping (value = "buscarPorNombre(nombre)")

    public Articulos buscarPorNombre (@PathVariable String nombre) {
        return articulosService.buscarPorNombre(nombre);
    }
}
