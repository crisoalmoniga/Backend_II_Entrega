// src/middlewares/passport.mid.js

import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { ExtractJwt, Strategy as JwtStrategy } from "passport-jwt";

import { usersManager } from "../data/managers/mongo/manager.mongo.js";
import { createHash, compareHash } from "../helpers/hash.helper.js";
import { createToken } from "../helpers/token.helper.js";

/* —————————————— */
/* 1) REGISTER */
/* —————————————— */
passport.use(
  "register",
  new LocalStrategy(
    { passReqToCallback: true, usernameField: "email" },
    async (req, email, password, done) => {
      try {
        if (!req.body.city) {
          return done(null, false, { message: "Invalid data", statusCode: 400 });
        }
        if (await usersManager.readBy({ email })) {
          return done(null, false, { message: "Invalid credentials", statusCode: 401 });
        }
        req.body.password = createHash(password);
        const user = await usersManager.createOne(req.body);
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

/* —————————————— */
/* 2) LOGIN */
/* —————————————— */
passport.use(
  "login",
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const user = await usersManager.readBy({ email });
        if (!user || !compareHash(password, user.password)) {
          return done(null, false, { message: "Invalid credentials", statusCode: 401 });
        }
        // generar token y guardarlo en user.token
        const payload = { user_id: user._id, email: user.email, role: user.role };
        user.token = createToken(payload);
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

/* —————————————— */
/* 3) JWT para USERS */
/* —————————————— */
passport.use(
  "user",
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,        // ← de tu .env
    },
    async (payload, done) => {
      try {
        const { user_id, email, role } = payload;
        const user = await usersManager.readBy({ _id: user_id, email, role });
        return user ? done(null, user) : done(null, false, { message: "Forbidden", statusCode: 403 });
      } catch (err) {
        return done(err, false);
      }
    }
  )
);

/* —————————————— */
/* 4) JWT para ADMIN */
/* —————————————— */
passport.use(
  "admin",
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
    },
    async (payload, done) => {
      try {
        const { user_id, email, role } = payload;
        const user = await usersManager.readBy({ _id: user_id, email, role });
        if (!user || user.role !== "ADMIN") {
          return done(null, false, { message: "Forbidden", statusCode: 403 });
        }
        return done(null, user);
      } catch (err) {
        return done(err, false);
      }
    }
  )
);

export default passport;