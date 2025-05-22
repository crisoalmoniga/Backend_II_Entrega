// src/config/passport/jwt.strategy.js
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';

const jwtOptions = {
  // extrae el token del header Authorization: Bearer <token>
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  // usa la variable de entorno que cargaste con dotenv/config al arrancar
  secretOrKey: process.env.JWT_SECRET
};

const verifyJwt = async (jwt_payload, done) => {
  try {
    return done(null, jwt_payload.user);
  } catch (err) {
    return done(err, false);
  }
};

export const initJwtStrategy = (passport) => {
  passport.use('jwt', new JwtStrategy(jwtOptions, verifyJwt));
};
