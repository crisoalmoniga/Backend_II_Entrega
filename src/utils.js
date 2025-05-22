import { dirname } from "path";
import { fileURLToPath } from "url";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';


const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default __dirname;

export const createHash = (password) =>
  bcrypt.hashSync(password, bcrypt.genSaltSync(10));

export const isValidPassword = (user, password) =>
  bcrypt.compareSync(password, user.password);

const JWT_SECRET = 'jwtSecret123'; // 👉 reemplazalo por process.env.JWT_SECRET si usás .env

export const generateToken = (user) => {
  const payload = { user: { id: user._id, email: user.email, role: user.role } };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
};
