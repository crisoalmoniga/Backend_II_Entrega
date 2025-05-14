class ProductManager {
    constructor() {
        this.products = []; // Inicializa un array vacío para almacenar productos
    }

    /**
     * Crea un nuevo producto y lo agrega a la lista de productos.
     * Asigna un ID único al producto y lo almacena en el array.
     */
    async crearProducto(producto) {
        try {
            producto.id = this.products.length + 1; // Asigna un ID único al producto
            this.products.push(producto); // Agrega el producto al array
            console.log('Producto creado exitosamente:', producto);
            return producto; // Devuelve el producto creado
        } catch (error) {
            console.error('Error al crear el producto:', error);
            throw error;
        }
    }

    /**
     * Devuelve la lista de todos los productos almacenados en memoria.
     */
    async leerProductos() {
        try {
            return this.products; // Devuelve el array de productos
        } catch (error) {
            console.error('Error al leer los productos:', error);
            throw error;
        }
    }

    /**
     * Actualiza un producto existente basado en su ID.
     * Fusiona los datos actualizados con los datos existentes del producto.
     */
    async actualizarProducto(id, productoActualizado) {
        try {
            const index = this.products.findIndex(prod => prod.id === id); // Busca el índice del producto
            if (index === -1) throw new Error('Producto no encontrado'); // Lanza un error si no existe

            this.products[index] = { ...this.products[index], ...productoActualizado }; // Actualiza el producto
            console.log('Producto actualizado:', this.products[index]);
            return this.products[index]; // Devuelve el producto actualizado
        } catch (error) {
            console.error('Error al actualizar el producto:', error);
            throw error;
        }
    }

    /**
     * Elimina un producto de la lista basado en su ID.
     * Devuelve el producto eliminado.
     */
    async eliminarProducto(id) {
        try {
            const index = this.products.findIndex(prod => prod.id === id); // Busca el índice del producto
            if (index === -1) throw new Error('Producto no encontrado'); // Lanza un error si no existe

            const eliminado = this.products.splice(index, 1); // Elimina el producto del array
            console.log('Producto eliminado:', eliminado[0]);
            return eliminado[0]; // Devuelve el producto eliminado
        } catch (error) {
            console.error('Error al eliminar el producto:', error);
            throw error;
        }
    }
}

export default ProductManager;