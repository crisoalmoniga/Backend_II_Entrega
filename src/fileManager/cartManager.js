class CartManager {
    constructor() {
        // Inicializa la clase con un array vacío para almacenar los carritos
        this.carts = []; // Almacén de carritos en memoria
    }

    crearCarrito() {
        // Crea un nuevo carrito con un ID único y un array vacío de productos
        const newCart = {
            id: this.carts.length + 1, // Generar un ID único basado en la longitud del array
            products: [] // Inicializa el carrito con una lista vacía de productos
        };
        this.carts.push(newCart); // Agrega el carrito a la lista de carritos
        console.log('Carrito creado:', newCart); // Imprime un mensaje en consola con el carrito creado
        return newCart; // Devuelve el carrito creado
    }

    agregarProductoAlCarrito(cartId, productId, quantity) {
        // Busca el carrito por su ID
        const cart = this.carts.find(cart => cart.id === cartId);
        if (!cart) {
            // Si el carrito no se encuentra, lanza un error
            throw new Error('Carrito no encontrado');
        }

        // Busca si el producto ya existe en el carrito
        const existingProduct = cart.products.find(p => p.productId === productId);
        if (existingProduct) {
            // Si el producto existe, incrementa su cantidad
            existingProduct.quantity += quantity; // Incrementar cantidad si el producto ya existe
        } else {
            // Si el producto no existe, lo agrega al carrito
            cart.products.push({ productId, quantity });
        }

        console.log(`Producto agregado al carrito ${cartId}:`, { productId, quantity }); // Imprime en consola el producto agregado
        return cart; // Devuelve el carrito actualizado
    }

    obtenerCarritos() {
        // Devuelve todos los carritos almacenados en memoria
        return this.carts;
    }

    obtenerCarritoPorId(cartId) {
        // Busca un carrito por su ID y lo devuelve
        // Si no encuentra el carrito, devuelve null
        return this.carts.find(cart => cart.id === cartId) || null;
    }

    eliminarProductoDelCarrito(cartId, productId) {
        // Busca el carrito por su ID
        const cart = this.carts.find(cart => cart.id === cartId);
        if (!cart) {
            // Si el carrito no se encuentra, lanza un error
            throw new Error('Carrito no encontrado');
        }

        // Filtra el array de productos para eliminar el producto con el ID especificado
        cart.products = cart.products.filter(p => p.productId !== productId);
        console.log(`Producto ${productId} eliminado del carrito ${cartId}`); // Imprime en consola el producto eliminado
        return cart; // Devuelve el carrito actualizado
    }

    eliminarCarrito(cartId) {
        // Encuentra el índice del carrito con el ID especificado
        const cartIndex = this.carts.findIndex(cart => cart.id === cartId);
        if (cartIndex === -1) {
            // Si el carrito no se encuentra, lanza un error
            throw new Error('Carrito no encontrado');
        }

        // Elimina el carrito del array y lo guarda en una variable
        const eliminado = this.carts.splice(cartIndex, 1);
        console.log(`Carrito eliminado:`, eliminado[0]); // Imprime en consola el carrito eliminado
        return eliminado[0]; // Devuelve el carrito eliminado
    }
}

export default CartManager; // Exporta la clase para su uso en otros archivos