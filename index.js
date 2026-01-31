const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');
const cors = require('cors');

const app = express();
const secretKey = 'your-secret-key';

// Middleware
app.use(bodyParser.json());
app.use(cors({
  origin: 'https://trebol-league.vercel.app',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (!bearerHeader) return res.sendStatus(403);

  try {
    const token = bearerHeader.split(' ')[1];
    req.user = jwt.verify(token, secretKey);
    next();
  } catch (err) {
    res.sendStatus(403);
  }
}

// Middleware roles
function requireLeagueRole(roles) {
  return async (req, res, next) => {
    const id_liga = req.params.id_liga || req.body.id_liga;
    if (!id_liga) return res.status(400).json({ message: 'Liga no especificada' });

    const result = await db.query(
      'SELECT rol FROM users_liga WHERE id_user = $1 AND id_liga = $2',
      [req.user.id, id_liga]
    );

    const rol = result.rows[0]?.rol;
    if (!rol || !roles.includes(rol)) return res.status(403).json({ message: 'No tienes permisos' });

    next();
  };
}

// Rutas públicas
app.get('/api/data', (req, res) => res.json({ message: 'This is public data' }));

app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Todos los campos son obligatorios." });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.query(
      "INSERT INTO users (username, email, password) VALUES ($1,$2,$3) RETURNING id",
      [username,email,hashedPassword]
    );
    res.status(201).json({ message:"Usuario registrado", userId: result.rows[0].id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error:"Error al registrar usuario." });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message:'Username y password requeridos' });

  try {
    const result = await db.query('SELECT * FROM users WHERE username=$1',[username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ message:'Usuario no existe' });

    const validPassword = await bcrypt.compare(password,user.password);
    if (!validPassword) return res.status(401).json({ message:'Contraseña incorrecta' });

    const token = jwt.sign({ id:user.id, username:user.username }, secretKey, { expiresIn:'30m' });
    res.json({ token });
  } catch(err) {
    console.error(err);
    res.status(500).json({ message:'Error en login' });
  }
});

app.get('/api/protected', verifyToken, (req,res) => res.json({ message:'Protected route', user:req.user }));

// --- Ligas ---
const router = express.Router();

router.post('/', verifyToken, async (req,res)=>{
  const { nombre, clave, max_jugadores } = req.body;
  const idUser = req.user.id;
  if (!nombre || !clave || !max_jugadores) return res.status(400).json({ message:'Todos los campos son obligatorios' });

  try {
    const result = await db.query(
      'INSERT INTO ligas (nombre, clave, max_jugadores) VALUES ($1,$2,$3) RETURNING id_liga',
      [nombre, clave, max_jugadores]
    );
    const idLiga = result.rows[0].id_liga;

    await db.query(
      'INSERT INTO users_liga (id_user, id_liga, rol, dinero, puntos) VALUES ($1,$2,$3,$4,$5)',
      [idUser, idLiga, 'owner', 100,0]
    );

    await db.query(
      'UPDATE ligas SET numero_jugadores=1 WHERE id_liga=$1',[idLiga]
    );

    res.status(201).json({ message:'Liga creada', id_liga:idLiga });
  } catch(err) {
    console.error(err);
    res.status(500).json({ message:'Error creando liga' });
  }
});

router.post('/:id_liga/join', verifyToken, async (req,res)=>{
  const idUser = req.user.id;
  const { id_liga } = req.params;
  const { clave } = req.body;

  try {
    const ligaResult = await db.query('SELECT * FROM ligas WHERE id_liga=$1',[id_liga]);
    if(!ligaResult.rows[0]) return res.status(404).json({ message:'Liga no encontrada' });

    const liga = ligaResult.rows[0];
    if(liga.clave !== clave) return res.status(403).json({ message:'Clave incorrecta' });
    if(liga.numero_jugadores >= liga.max_jugadores) return res.status(403).json({ message:'Liga llena' });

    await db.query('INSERT INTO users_liga (id_user,id_liga,rol,dinero,puntos) VALUES ($1,$2,$3,$4,$5)',
      [idUser, id_liga, 'user',100,0]
    );
    await db.query('UPDATE ligas SET numero_jugadores = numero_jugadores + 1 WHERE id_liga=$1',[id_liga]);

    res.json({ message:'Te has unido a la liga', id_liga });
  } catch(err) {
    console.error(err);
    if(err.code==='23505') return res.status(400).json({ message:'Ya estás en esta liga' });
    res.status(500).json({ message:'Error al unirse a la liga' });
  }
});

router.delete('/:id_liga', verifyToken, requireLeagueRole(['owner']), async(req,res)=>{
  const { id_liga } = req.params;
  try {
    await db.query('DELETE FROM users_liga WHERE id_liga=$1',[id_liga]);
    await db.query('DELETE FROM ligas WHERE id_liga=$1',[id_liga]);
    res.json({ message:'Liga eliminada' });
  } catch(err){
    console.error(err);
    res.status(500).json({ message:'Error eliminando liga' });
  }
});

router.put('/:id_liga/make-admin/:id_user', verifyToken, requireLeagueRole(['owner']), async(req,res)=>{
  const { id_liga, id_user } = req.params;
  try{
    await db.query('UPDATE users_liga SET rol=$1 WHERE id_user=$2 AND id_liga=$3',['admin',id_user,id_liga]);
    res.json({ message:'Usuario ascendido a admin' });
  }catch(err){
    console.error(err);
    res.status(500).json({ message:'Error al ascender a admin' });
  }
});

app.use('/api/ligas', router);

app.get('/api/mis-ligas', verifyToken, async(req,res)=>{
  try{
    const result = await db.query(
      `SELECT l.id_liga,l.nombre,ul.dinero,ul.puntos,ul.rol
       FROM users_liga ul
       JOIN ligas l ON l.id_liga=ul.id_liga
       WHERE ul.id_user=$1`,[req.user.id]
    );
    res.json(result.rows);
  }catch(err){
    console.error(err);
    res.status(500).json({ error:'Error obteniendo ligas' });
  }
});

// ✅ Export para Vercel serverless
module.exports = app;
