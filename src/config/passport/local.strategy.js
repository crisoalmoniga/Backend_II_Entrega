import { Strategy as LocalStrategy } from 'passport-local';
import UserModel from '../../models/user.model.js';
import { isValidPassword } from '../../utils.js';

const strategyOptions = {
  usernameField: 'email',
  passwordField: 'password',
  passReqToCallback: false,
};

const verifyCallback = async (email, password, done) => {
  try {
    const user = await UserModel.findOne({ email });
    if (!user) return done(null, false, { message: 'Usuario no encontrado' });

    if (!isValidPassword(user, password)) {
      return done(null, false, { message: 'Contraseña incorrecta' });
    }

    return done(null, user);
  } catch (err) {
    return done(err);
  }
};

export const initLocalStrategy = (passport) => {
  passport.use('login', new LocalStrategy(strategyOptions, verifyCallback));
};