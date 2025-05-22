import passport from 'passport';
import { initLocalStrategy } from './local.strategy.js';
import { initJwtStrategy } from './jwt.strategy.js';

export const initPassport = () => {
  initLocalStrategy(passport);
  initJwtStrategy(passport);
};
