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

// Protected route
app.get('/api/protected', verifyToken, (req, res) => {
  jwt.verify(req.token, secretKey, (err, authData) => {
    if (err) {
      res.sendStatus(403);
    } else {
      res.json({
        message: 'This is protected data',
        authData
      });
    }
  });
});

// Middleware para verificar token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined') {
    const bearer = bearerHeader.split(' ');
    const bearerToken = bearer[1];
    req.token = bearerToken;
    next();
  } else {
    res.sendStatus(403);
  }
}

app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});

// crear la liga

router.post('/', verifyToken, async (req, res) => {
  const { nombre, clave, max_jugadores } = req.body;
  const idUser = req.user.id;

  if (!nombre || !clave || !max_jugadores)
    return res.status(400).json({ message: 'Todos los campos son obligatorios' });

  try {
    const result = await db.query(
      'INSERT INTO ligas (nombre, clave, max_jugadores) VALUES ($1, $2, $3) RETURNING id_liga',
      [nombre, clave, max_jugadores]
    );
    const idLiga = result.rows[0].id_liga;

    // El que crea la liga se une automaticamnte como owner
    await db.query(
      'INSERT INTO users_liga (id_user, id_liga, rol) VALUES ($1, $2, $3)',
      [idUser, idLiga, 'owner']
    );

    // Incrementamos numero de jugadores
    await db.query(
      'UPDATE ligas SET numero_jugadores = numero_jugadores + 1 WHERE id_liga = $1',
      [idLiga]
    );

    res.status(201).json({ message: 'Liga creada', id_liga: idLiga });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creando liga' });
  }
});

// unirse a liga

router.post('/join', verifyToken, async (req, res) => {
  const { nombre, clave } = req.body;
  const idUser = req.user.id;

  try {
    const ligaResult = await db.query(
      'SELECT * FROM ligas WHERE nombre = $1 AND clave = $2',
      [nombre, clave]
    );

    if (ligaResult.rows.length === 0)
      return res.status(404).json({ message: 'Liga no encontrada o clave incorrecta' });

    const liga = ligaResult.rows[0];

    if (liga.numero_jugadores >= liga.max_jugadores)
      return res.status(403).json({ message: 'Liga llena' });

    await db.query(
      'INSERT INTO users_liga (id_user, id_liga) VALUES ($1, $2)',
      [idUser, liga.id_liga]
    );

    await db.query(
      'UPDATE ligas SET numero_jugadores = numero_jugadores + 1 WHERE id_liga = $1',
      [liga.id_liga]
    );

    res.json({ message: 'Te has unido a la liga', id_liga: liga.id_liga });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') {
      return res.status(400).json({ message: 'Ya estás en esta liga' });
    }
    res.status(500).json({ message: 'Error al unirse a la liga' });
  }
});

// solo owner puede eliminar liga

router.delete('/:id_liga', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
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

module.exports = router;


// ver ligas de 1 usuarrio

app.get('/api/mis-ligas', verifyToken, async (req, res) => {
  const decoded = jwt.verify(req.token, secretKey);

  try {
    const result = await db.query(`
      SELECT l.id_liga, l.nombre, ul.dinero, ul.puntos
      FROM users_liga ul
      JOIN ligas l ON l.id_liga = ul.id_liga
      WHERE ul.id_user = $1
    `, [decoded.id]);

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo ligas' });
  }
});

// asignar owner al crear la liga autimatico

app.post('/api/ligas', verifyToken, async (req, res) => {
  const { nombre } = req.body;
  const userId = req.user.id;

  try {
    // Creo liga
    const ligaResult = await db.query(
      'INSERT INTO ligas (nombre) VALUES ($1) RETURNING id_liga',
      [nombre]
    );

    const id_liga = ligaResult.rows[0].id_liga;

    // Meto al creador como OWNER
    await db.query(
      `INSERT INTO users_liga (id_user, id_liga, dinero, puntos, rol)
       VALUES ($1, $2, 100, 0, 'owner')`,
      [userId, id_liga]
    );

    res.status(201).json({
      message: 'Liga creada',
      id_liga,
      rol: 'owner'
    });

  } catch (err) {
    res.status(500).json({ error: 'Error creando liga' });
  }
});

// si te unes a la liga eres user

app.post('/api/ligas/:id_liga/join', verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { id_liga } = req.params;

  try {
    await db.query(
      `INSERT INTO users_liga (id_user, id_liga, dinero, puntos, rol)
       VALUES ($1, $2, 100, 0, 'user')`,
      [userId, id_liga]
    );

    res.json({ message: 'Te has unido a la liga', rol: 'user' });

  } catch (err) {
    res.status(500).json({ error: 'No se pudo unir a la liga' });
  }
});

// eliminar liga

app.delete(
  '/api/ligas/:id_liga',
  verifyToken,
  requireLeagueRole(['owner']),
  async (req, res) => {
    await db.query(
      'DELETE FROM ligas WHERE id_liga = $1',
      [req.params.id_liga]
    );

    res.json({ message: 'Liga eliminada' });
  }
);

// hacer admin

app.put(
  '/api/ligas/:id_liga/make-admin/:id_user',
  verifyToken,
  requireLeagueRole(['owner']),
  async (req, res) => {

    const { id_liga, id_user } = req.params;

    await db.query(
      `UPDATE users_liga
       SET rol = 'admin'
       WHERE id_user = $1 AND id_liga = $2`,
      [id_user, id_liga]
    );

    res.json({ message: 'Usuario ascendido a admin' });
  }
);

// 🔹 Server
app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
