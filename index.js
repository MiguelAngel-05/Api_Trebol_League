const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');
const router = express.Router(); // para ligas

const app = express();
const port = process.env.PORT || 3000;
const secretKey = 'your-secret-key';

// Body parser
app.use(bodyParser.json());

// 🔹 Middleware CORS para Vercel
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://trebol-league.vercel.app');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// 🔹 Middleware token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (!bearerHeader) return res.sendStatus(403);

  const token = bearerHeader.split(' ')[1];
  req.token = token;

  try {
    req.user = jwt.verify(token, secretKey);
    next();
  } catch (err) {
    res.sendStatus(403);
  }
}

// 🔹 Public route
app.get('/api/data', (req, res) => {
  res.json({ message: 'This is public data' });
});

// 🔹 Register
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: "Todos los campos son obligatorios." });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id",
      [username, email, hashedPassword]
    );
    res.status(201).json({ message: "Usuario registrado", userId: result.rows[0].id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al registrar usuario." });
  }
});

// 🔹 Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Username y password requeridos' });

  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ message: 'Usuario no existe' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ message: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '30m' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error en login' });
  }
});

// 🔹 Mis ligas
app.get('/api/mis-ligas', verifyToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT l.id_liga, l.nombre, ul.dinero, ul.puntos
      FROM users_liga ul
      JOIN ligas l ON l.id_liga = ul.id_liga
      WHERE ul.id_user = $1
    `, [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo ligas' });
  }
});

// 🔹 Router ligas (crear, unirse, eliminar, make-admin)
// Aquí metes todas tus rutas de ligas que antes estaban en router
// Ejemplo: router.post('/', verifyToken, async ... )
// Al final, conectamos el router al app:
app.use('/api/ligas', router);

// 🔹 Server
app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
