import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { engine } from 'express-handlebars';
import mongoose from 'mongoose';
import __dirname from './utils.js';
import ProductModel from './models/product.model.js';

// Routers
import productsRouter from './routes/products.router.js';
import cartsRouter from './routes/carts.router.js';

const app = express();
const server = createServer(app);
const io = new Server(server);

// Conectar a MongoDB
const MONGO_URL = 'mongodb+srv://cristianalmoniga:Q8ggX0DhjCOe9fmT@cluster0.miur3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const connectDB = async () => {
    try {
        await mongoose.connect(MONGO_URL, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('Conectado a MongoDB');
    } catch (error) {
        console.error('Error al conectar a MongoDB:', error);
        process.exit(1);
    }
};
connectDB();

// Configurar Handlebars como motor de plantillas
app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.set('views', __dirname + '/views');

// Middleware para manejar JSON y formularios
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir archivos estáticos
app.use('/static', express.static(__dirname + '/public'));

// Rutas
app.use('/api/products', productsRouter);
app.use('/api/carts', cartsRouter);

// Ruta para la vista de productos en tiempo real con .lean()
app.get('/realtimeproducts', async (req, res) => {
    const products = await ProductModel.find().lean();
    res.render('realTimeProducts', { products });
});

// WebSockets
io.on('connection', (socket) => {
    console.log('Cliente conectado');

    const emitirProductosActualizados = async () => {
        const products = await ProductModel.find().lean();
        io.emit('updateProducts', products);
    };

    socket.on('newProduct', async () => {
        await emitirProductosActualizados();
    });

    socket.on('deleteProduct', async () => {
        await emitirProductosActualizados();
    });

    socket.on('disconnect', () => {
        console.log('Cliente desconectado');
    });
});

// Exportar io para su uso en otros módulos
export { io };

// Inicialización del servidor
const PORT = 8080;
server.listen(PORT, () => {
    console.log(`Servidor escuchando en el puerto ${PORT}`);
});