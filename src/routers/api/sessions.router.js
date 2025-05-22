import { Router } from 'express';
import passport from 'passport';
import { generateToken } from '../../utils.js';
import { createCb, readCb, destroyCb } from '../../controllers/sessions.controller.js';

const router = Router();

// Rutas CRUD
router.get('/create', createCb);
router.get('/read', readCb);
router.get('/destroy', destroyCb);

// Login con estrategia local y JWT
router.post('/login', (req, res, next) => {
  passport.authenticate('login', { session: false }, (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrecta' });

    const token = generateToken(user);
    return res.json({ token });
  })(req, res, next);
});

export default router;

// Ruta protegida que devuelve los datos del usuario logueado
router.get(
  '/current',
  passport.authenticate('user', { session: false }),
  (req, res) => res.json({ user: req.user })
);