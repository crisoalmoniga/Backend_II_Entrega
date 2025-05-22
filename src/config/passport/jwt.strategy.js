import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: 'jwtSecret123', // ⚠️ reemplazá por process.env.JWT_SECRET si tenés .env
};

const verifyJwt = async (jwt_payload, done) => {
  try {
    return done(null, jwt_payload.user);
  } catch (err) {
    return done(err);
  }
};

export const initJwtStrategy = (passport) => {
  passport.use('jwt', new JwtStrategy(jwtOptions, verifyJwt));
};