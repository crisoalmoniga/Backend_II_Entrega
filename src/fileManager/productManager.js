import fs from 'fs/promises';

class ProductManager {
    constructor(filePath = './src/fileManager/products.json') {
        this.filePath = filePath;
    }

    async crearProducto(product) {
        try {
            let productos = await this.leerProductos();
            product.id = productos.length ? productos[productos.length - 1].id + 1 : 1;
            productos.push(product);
            await fs.writeFile(this.filePath, JSON.stringify(productos, null, 2));
            console.log('Producto creado exitosamente:', product);
            return product;
        } catch (error) {
            console.error('Error al crear un producto:', error);
            throw error;
        }
    }

    async leerProductos() {
        try {
            const data = await fs.readFile(this.filePath, 'utf-8');
            return JSON.parse(data) || [];
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log('El archivo no existe, creando uno nuevo...');
                await fs.writeFile(this.filePath, '[]');
                return [];
            } else {
                console.error('Error al leer productos:', error);
                throw error;
            }
        }
    }

    async actualizarProducto(id, productoActualizado) {
        try {
            const productos = await this.leerProductos();
            const index = productos.findIndex(prod => prod.id === id);
            if (index === -1) throw new Error('Producto no encontrado');
            productos[index] = { ...productos[index], ...productoActualizado };
            await fs.writeFile(this.filePath, JSON.stringify(productos, null, 2));
            console.log('Producto actualizado:', productos[index]);
        } catch (error) {
            console.error('Error al actualizar el producto:', error);
            throw error;
        }
    }

    async eliminarProducto(id) {
        try {
            const productos = await this.leerProductos();
            const nuevoProductos = productos.filter(prod => prod.id !== id);
            await fs.writeFile(this.filePath, JSON.stringify(nuevoProductos, null, 2));
            console.log(`Producto con ID ${id} eliminado`);
        } catch (error) {
            console.error('Error al eliminar el producto:', error);
            throw error;
        }
    }

    async obtenerProductoPorId(id) {
        try {
            const productos = await this.leerProductos();
            return productos.find(prod => prod.id === id) || null;
        } catch (error) {
            console.error('Error al obtener el producto:', error);
            throw error;
        }
    }
}

export default ProductManager;