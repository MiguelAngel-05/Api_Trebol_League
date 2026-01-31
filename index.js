const express = require('express');
const serverless = require('serverless-http'); // para Vercel
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');

const app = express();
const router = express.Router(); // rutas de ligas
const secretKey = 'your-secret-key';

// Middleware body parser
app.use(bodyParser.json());

// 🔹 Middleware CORS para frontend
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
  try {
    req.user = jwt.verify(token, secretKey);
    next();
  } catch (err) {
    res.sendStatus(403);
  }
}

// 🔹 Middleware para verificar rol en ligas
async function requireLeagueRole(roles) {
  return async (req, res, next) => {
    const { id_liga } = req.params;
    const userId = req.user.id;

    try {
      const result = await db.query(
        'SELECT rol FROM users_liga WHERE id_user=$1 AND id_liga=$2',
        [userId, id_liga]
      );
      const userRole = result.rows[0]?.rol;
      if (!userRole || !roles.includes(userRole)) return res.sendStatus(403);
      next();
    } catch (err) {
      console.error(err);
      res.sendStatus(500);
    }
  };
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

// 🔹 Protected route ejemplo
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({ message: 'This is protected data', user: req.user });
});


// =======================
// 🔹 RUTAS DE LIGAS
// =======================

// Crear liga
router.post('/', verifyToken, async (req, res) => {
  const { nombre, clave, max_jugadores } = req.body;
  const userId = req.user.id;

  if (!nombre || !clave || !max_jugadores)
    return res.status(400).json({ message: 'Todos los campos son obligatorios' });

  try {
    const result = await db.query(
      'INSERT INTO ligas (nombre, clave, max_jugadores) VALUES ($1, $2, $3) RETURNING id_liga',
      [nombre, clave, max_jugadores]
    );
    const id_liga = result.rows[0].id_liga;

    // Creador se une como owner
    await db.query(
      'INSERT INTO users_liga (id_user, id_liga, rol, dinero, puntos) VALUES ($1, $2, $3, 100, 0)',
      [userId, id_liga, 'owner']
    );

    res.status(201).json({ message: 'Liga creada', id_liga, rol: 'owner' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creando liga' });
  }
});

// Unirse a liga
router.post('/:id_liga/join', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const userId = req.user.id;

  try {
    const ligaResult = await db.query('SELECT * FROM ligas WHERE id_liga=$1', [id_liga]);
    const liga = ligaResult.rows[0];
    if (!liga) return res.status(404).json({ message: 'Liga no encontrada' });

    const usersCount = await db.query(
      'SELECT COUNT(*) FROM users_liga WHERE id_liga=$1',
      [id_liga]
    );

    if (parseInt(usersCount.rows[0].count) >= liga.max_jugadores)
      return res.status(403).json({ message: 'Liga llena' });

    await db.query(
      'INSERT INTO users_liga (id_user, id_liga, rol, dinero, puntos) VALUES ($1, $2, $3, 100, 0)',
      [userId, id_liga, 'user']
    );

    res.json({ message: 'Te has unido a la liga', rol: 'user' });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') return res.status(400).json({ message: 'Ya estás en esta liga' });
    res.status(500).json({ message: 'Error al unirse a la liga' });
  }
});

// Eliminar liga (solo owner)
router.delete('/:id_liga', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
  const { id_liga } = req.params;
  try {
    await db.query('DELETE FROM users_liga WHERE id_liga=$1', [id_liga]);
    await db.query('DELETE FROM ligas WHERE id_liga=$1', [id_liga]);
    res.json({ message: 'Liga eliminada' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error eliminando liga' });
  }
});

// Hacer admin (solo owner)
router.put('/:id_liga/make-admin/:id_user', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
  const { id_liga, id_user } = req.params;
  try {
    await db.query('UPDATE users_liga SET rol=$1 WHERE id_user=$2 AND id_liga=$3', ['admin', id_user, id_liga]);
    res.json({ message: 'Usuario ascendido a admin' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al ascender usuario' });
  }
});

// Ver mis ligas
app.get('/api/mis-ligas', verifyToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await db.query(`
      SELECT l.id_liga, l.nombre, ul.dinero, ul.puntos, ul.rol
      FROM users_liga ul
      JOIN ligas l ON l.id_liga = ul.id_liga
      WHERE ul.id_user=$1
    `, [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error obteniendo ligas' });
  }
});

// Montar router de ligas
app.use('/api/ligas', router);

// 🔹 Export para Vercel
module.exports.handler = serverless(app);
