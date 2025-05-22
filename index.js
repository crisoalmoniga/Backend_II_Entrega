// index.js
import 'dotenv/config';                 // 1) carga .env
import express from 'express';
import passport from 'passport';
import { engine } from 'express-handlebars';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import MongoStore from 'connect-mongo';

import __dirname from './src/utils.js';
import argvsHelper from './src/helpers/argvs.helper.js';
import dbConnect from './src/helpers/dbConnect.helper.js';
import indexRouter from './src/routers/index.router.js';
import pathHandler from './src/middlewares/pathHandler.mid.js';
import errorHandler from './src/middlewares/errorHandler.mid.js';

import { initLocalStrategy } from './src/config/passport/local.strategy.js';
import { initJwtStrategy }   from './src/config/passport/jwt.strategy.js';

const app = express();
const PORT = process.env.PORT || 8080;

// 2) inicializar estrategias **después** de haber cargado .env
initLocalStrategy(passport);
initJwtStrategy(passport);
app.use(passport.initialize());

// 3) Conectar DB y arrancar
const ready = async () => {
  await dbConnect(process.env.MONGO_URL);
  console.log(`🚀 Server on http://localhost:${PORT} [mode: ${argvsHelper.mode}]`);
};
app.listen(PORT, ready);

// 4) resto de tu setup
app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.set('views', `${__dirname}/src/views`);
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.SESSION_SECRET));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URL }),
    cookie: { maxAge: 60_000 },
  })
);
app.use(express.static('public'));
app.use('/', indexRouter);
app.use(errorHandler);
app.use(pathHandler);