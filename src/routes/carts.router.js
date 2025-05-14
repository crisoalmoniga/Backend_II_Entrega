import { Router } from "express";
import mongoose from "mongoose"; // Importamos mongoose para manejar ObjectId
import Cart from "../models/cart.model.js";
import Product from "../models/product.model.js";

const router = Router();

// Crear un nuevo carrito vacío
router.post("/", async (req, res) => {
    try {
        const newCart = await Cart.create({ products: [] });
        res.status(201).json(newCart);
    } catch (error) {
        res.status(500).json({ error: "Error al crear el carrito", details: error.message });
    }
});

// Obtener un carrito por ID (con los productos populados)
router.get("/:cid", async (req, res) => {
    try {
        const { cid } = req.params;
        const cart = await Cart.findById(new mongoose.Types.ObjectId(cid)).populate("products.product");

        if (!cart) {
            return res.status(404).json({ error: "Carrito no encontrado" });
        }

        res.json(cart);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener el carrito", details: error.message });
    }
});

// Obtener todos los carritos
router.get("/", async (req, res) => {
    try {
        const carts = await Cart.find();
        res.json(carts);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener los carritos", details: error.message });
    }
});


// Agregar un producto a un carrito
router.post("/:cid/products/:pid", async (req, res) => {
    try {
        const { cid, pid } = req.params;

        // Validar si el producto existe en la base de datos
        const productExists = await Product.findById(pid);
        if (!productExists) {
            return res.status(404).json({ error: "Producto no encontrado" });
        }

        // Convertir `cid` a ObjectId antes de buscar el carrito
        let cart = await Cart.findById(new mongoose.Types.ObjectId(cid));
        if (!cart) {
            return res.status(404).json({ error: "Carrito no encontrado" });
        }

        // Buscar si el producto ya está en el carrito
        const productIndex = cart.products.findIndex(p => p.product.toString() === pid);

        if (productIndex !== -1) {
            // Si el producto ya está en el carrito, incrementamos la cantidad
            cart.products[productIndex].quantity += req.body.quantity || 1;
        } else {
            // Si no está en el carrito, lo agregamos con la cantidad indicada
            cart.products.push({ product: pid, quantity: req.body.quantity || 1 });
        }

        await cart.save();
        res.json(cart);
    } catch (error) {
        res.status(500).json({ error: "Error al agregar producto al carrito", details: error.message });
    }
});

export default router;