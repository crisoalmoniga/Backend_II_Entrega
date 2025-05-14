import { Router } from 'express';
import ProductModel from '../models/product.model.js';

const router = Router();

// Obtener todos los productos con paginación, filtros y ordenamiento
router.get('/', async (req, res) => {
    try {
        const { page = 1, limit = 10, sort, query } = req.query;
        const options = {
            page: parseInt(page),
            limit: parseInt(limit),
            sort: sort === 'asc' ? { price: 1 } : sort === 'desc' ? { price: -1 } : {},
        };

        // Construcción de filtro dinámico
        let filter = {};
        if (query) {
            filter = { $or: [{ category: query }, { availability: query }] };
        }

        const products = await ProductModel.paginate(filter, options);

        res.json({
            status: 'success',
            payload: products.docs,
            totalPages: products.totalPages,
            prevPage: products.prevPage,
            nextPage: products.nextPage,
            page: products.page,
            hasPrevPage: products.hasPrevPage,
            hasNextPage: products.hasNextPage,
            prevLink: products.hasPrevPage ? `/api/products?page=${products.prevPage}&limit=${limit}` : null,
            nextLink: products.hasNextPage ? `/api/products?page=${products.nextPage}&limit=${limit}` : null,
        });
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener los productos', details: error.message });
    }
});

// Obtener un producto por ID
router.get('/:id', async (req, res) => {
    try {
        const product = await ProductModel.findById(req.params.id);
        if (!product) {
            return res.status(404).json({ error: 'Producto no encontrado' });
        }
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener el producto', details: error.message });
    }
});

// Agregar un nuevo producto
router.post('/', async (req, res) => {
    try {
        const newProduct = new ProductModel(req.body);
        await newProduct.save();
        res.status(201).json({ message: 'Producto agregado', product: newProduct });
    } catch (error) {
        res.status(500).json({ error: 'Error al agregar el producto', details: error.message });
    }
});

// Actualizar un producto por ID
router.put('/:id', async (req, res) => {
    try {
        const updatedProduct = await ProductModel.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!updatedProduct) {
            return res.status(404).json({ error: 'Producto no encontrado' });
        }
        res.json({ message: 'Producto actualizado', product: updatedProduct });
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar el producto', details: error.message });
    }
});

// Eliminar un producto por ID
router.delete('/:id', async (req, res) => {
    try {
        const deletedProduct = await ProductModel.findByIdAndDelete(req.params.id);
        if (!deletedProduct) {
            return res.status(404).json({ error: 'Producto no encontrado' });
        }
        res.json({ message: 'Producto eliminado', product: deletedProduct });
    } catch (error) {
        res.status(500).json({ error: 'Error al eliminar el producto', details: error.message });
    }
});

export default router;