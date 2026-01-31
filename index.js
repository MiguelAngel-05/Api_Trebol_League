const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');

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

// 🔹 Middleware para verificar token
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

// 🔹 Middleware para verificar rol en liga
async function requireLeagueRole(roles) {
  return async (req, res, next) => {
    const { id_liga, id_user } = req.params;
    const userId = req.user.id;

    const result = await db.query(
      'SELECT rol FROM users_liga WHERE id_user = $1 AND id_liga = $2',
      [userId, id_liga || id_user]
    );

    if (!result.rows[0] || !roles.includes(result.rows[0].rol)) {
      return res.status(403).json({ message: 'No tienes permisos' });
    }

    next();
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

// 🔹 Ver ligas de 1 usuario
app.get('/api/mis-ligas', verifyToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT l.id_liga, l.nombre, ul.dinero, ul.puntos, ul.rol
      FROM users_liga ul
      JOIN ligas l ON l.id_liga = ul.id_liga
      WHERE ul.id_user = $1
    `, [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo ligas' });
  }
});

// 🔹 Crear liga
app.post('/api/ligas', verifyToken, async (req, res) => {
  const { nombre, clave, max_jugadores } = req.body;
  const userId = req.user.id;
  if (!nombre || !clave || !max_jugadores) return res.status(400).json({ message: 'Todos los campos son obligatorios' });

  try {
    const result = await db.query(
      'INSERT INTO ligas (nombre, clave, max_jugadores) VALUES ($1, $2, $3) RETURNING id_liga',
      [nombre, clave, max_jugadores]
    );
    const id_liga = result.rows[0].id_liga;

    await db.query(
      `INSERT INTO users_liga (id_user, id_liga, dinero, puntos, rol)
       VALUES ($1, $2, 100, 0, 'owner')`,
      [userId, id_liga]
    );

    await db.query(
      'UPDATE ligas SET numero_jugadores = 1 WHERE id_liga = $1',
      [id_liga]
    );

    res.status(201).json({ message: 'Liga creada', id_liga, rol: 'owner' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creando liga' });
  }
});

// 🔹 Unirse a liga
app.post('/api/ligas/:id_liga/join', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const { nombre, clave } = req.body;
  const userId = req.user.id;

  try {
    const ligaResult = await db.query('SELECT * FROM ligas WHERE id_liga = $1 AND nombre = $2 AND clave = $3', [id_liga, nombre, clave]);
    if (!ligaResult.rows[0]) return res.status(404).json({ message: 'Liga no encontrada o clave incorrecta' });

    const liga = ligaResult.rows[0];
    if (liga.numero_jugadores >= liga.max_jugadores) return res.status(403).json({ message: 'Liga llena' });

    await db.query(
      `INSERT INTO users_liga (id_user, id_liga, dinero, puntos, rol)
       VALUES ($1, $2, 100, 0, 'user')`,
      [userId, id_liga]
    );

    await db.query(
      'UPDATE ligas SET numero_jugadores = numero_jugadores + 1 WHERE id_liga = $1',
      [id_liga]
    );

    res.json({ message: 'Te has unido a la liga', rol: 'user' });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') return res.status(400).json({ message: 'Ya estás en esta liga' });
    res.status(500).json({ message: 'Error al unirse a la liga' });
  }
});

// 🔹 Eliminar liga (solo owner)
app.delete('/api/ligas/:id_liga', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
  const { id_liga } = req.params;
  try {
    await db.query('DELETE FROM users_liga WHERE id_liga = $1', [id_liga]);
    await db.query('DELETE FROM ligas WHERE id_liga = $1', [id_liga]);
    res.json({ message: 'Liga eliminada' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error eliminando liga' });
  }
});

// 🔹 Hacer admin (solo owner)
app.put('/api/ligas/:id_liga/make-admin/:id_user', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
  const { id_liga, id_user } = req.params;
  try {
    await db.query(`UPDATE users_liga SET rol='admin' WHERE id_user=$1 AND id_liga=$2`, [id_user, id_liga]);
    res.json({ message: 'Usuario ascendido a admin' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error asignando admin' });
  }
});

// 🔹 Server
app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
