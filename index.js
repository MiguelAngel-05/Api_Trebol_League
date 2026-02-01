const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');
const cors = require('cors');

const app = express();
const secretKey = 'your-secret-key';

const mercadoRouter = express.Router();

app.use(bodyParser.json());

// CORS para permitir que el front de vercel haga peticiones al back porque daba errores
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://trebol-league.vercel.app'); // o '*' si quieres permitir todos
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // Responde a preflight OPTIONS
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

// esto es para la autenticacion

// verifica si el usuario envia un token valido
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

// comprueba si el usuario tiene un rol específico dentro de la liga
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

// ruta publica de prueba
app.get('/api/data', (req, res) => res.json({ message: 'This is public data' }));

// registro de usuario
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

// login de usuario
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

// ruta protegida de prueba
app.get('/api/protected', verifyToken, (req,res) => res.json({ message:'Protected route', user:req.user }));


// rutas de ligas

const router = express.Router();

// crear una liga
router.post('/', verifyToken, async (req,res)=>{
  const { nombre, clave, max_jugadores } = req.body;
  const idUser = req.user.id;

  if (!nombre || !clave || !max_jugadores) return res.status(400).json({ message:'Todos los campos son obligatorios' });

  try {
    // crear la liga en la tabla de ligas
    const result = await db.query(
      'INSERT INTO ligas (nombre, clave, max_jugadores) VALUES ($1,$2,$3) RETURNING id_liga',
      [nombre, clave, max_jugadores]
    );
    const idLiga = result.rows[0].id_liga;

    // añadiral creador en users_liga como owner con dinero y puntos iniciales
    await db.query(
      'INSERT INTO users_liga (id_user, id_liga, rol, dinero, puntos) VALUES ($1,$2,$3,$4,$5)',
      [idUser, idLiga, 'owner', 10000000,0]
    );

    // atualizar el numero de jugadores a 1
    await db.query('UPDATE ligas SET numero_jugadores=1 WHERE id_liga=$1',[idLiga]);

    res.status(201).json({ message:'Liga creada', id_liga:idLiga });
  } catch(err) {
    console.error(err);
    res.status(500).json({ message:'Error creando liga' });
  }
});

// obtener id de liga por nombre y clave
router.post('/get-id-by-credentials', verifyToken, async (req, res) => {
  const { nombre, clave } = req.body;

  if (!nombre || !clave) {
    return res.status(400).json({ message: 'Nombre y clave requeridos' });
  }

  try {
    const result = await db.query(
      'SELECT id_liga FROM ligas WHERE nombre = $1 AND clave = $2',
      [nombre, clave]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Liga no encontrada o clave incorrecta' });
    }

    res.json({ id_liga: result.rows[0].id_liga });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error obteniendo la liga' });
  }
});


// unirse a una liga 
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

    // insertar al usuario como user en la liga
    await db.query('INSERT INTO users_liga (id_user,id_liga,rol,dinero,puntos) VALUES ($1,$2,$3,$4,$5)',
      [idUser, id_liga, 'user',10000000,0]
    );

    // aumentar el numero de jugadores
    await db.query('UPDATE ligas SET numero_jugadores = numero_jugadores + 1 WHERE id_liga=$1',[id_liga]);

    res.json({ message:'Te has unido a la liga', id_liga });
  } catch(err) {
    console.error(err);
    if(err.code==='23505') return res.status(400).json({ message:'Ya estás en esta liga' });
    res.status(500).json({ message:'Error al unirse a la liga' });
  }
});

// eliminar una liga (solo el owner)
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

// ascender un usuario a admin (solo owner)
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

// Ver ligas de un usuario
app.get('/api/mis-ligas', verifyToken, async(req,res)=>{
  try{
    const result = await db.query(
      `SELECT l.id_liga,l.nombre,l.numero_jugadores,l.max_jugadores,ul.dinero,ul.puntos,ul.rol
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


// ver mercado de la liga
mercadoRouter.get('/:id_liga', verifyToken, async (req, res) => {
  const { id_liga } = req.params;

  try {
    const result = await db.query(`
      SELECT f.id_futbolista, f.nombre, f.posicion, f.dorsal, f.precio
      FROM futbolistas f
      WHERE f.id_futbolista NOT IN (
        SELECT id_futbolista
        FROM futbolista_user_liga
        WHERE id_liga = $1
      )
    `, [id_liga]);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error obteniendo mercado' });
  }
});

// comprar a un jugadorr
mercadoRouter.post('/:id_liga/comprar/:id_futbolista', verifyToken, async (req, res) => {
  const { id_liga, id_futbolista } = req.params;
  const id_user = req.user.id;

  try {
    // veo el precio del futbolista
    const futbolistaResult = await db.query(
      'SELECT precio FROM futbolistas WHERE id_futbolista = $1',
      [id_futbolista]
    );

    if (!futbolistaResult.rows[0]) {
      return res.status(404).json({ message: 'Futbolista no existe' });
    }

    const precio = futbolistaResult.rows[0].precio;

    // veo el dinero del que ficha en la liga
    const userLiga = await db.query(
      'SELECT dinero FROM users_liga WHERE id_user = $1 AND id_liga = $2',
      [id_user, id_liga]
    );

    if (!userLiga.rows[0]) {
      return res.status(403).json({ message: 'No estás en esta liga' });
    }

    if (userLiga.rows[0].dinero < precio) {
      return res.status(400).json({ message: 'No tienes dinero suficiente' });
    }

    // comprobamos de q si ya esta comprado
    const exists = await db.query(
      'SELECT 1 FROM futbolista_user_liga WHERE id_liga=$1 AND id_futbolista=$2',
      [id_liga, id_futbolista]
    );

    if (exists.rows.length > 0) {
      return res.status(400).json({ message: 'Este futbolista ya está en esta liga' });
    }

    // 4. se compra
    await db.query(
      'INSERT INTO futbolista_user_liga (id_user, id_liga, id_futbolista) VALUES ($1,$2,$3)',
      [id_user, id_liga, id_futbolista]
    );

    await db.query(
      'UPDATE users_liga SET dinero = dinero - $1 WHERE id_user=$2 AND id_liga=$3',
      [precio, id_user, id_liga]
    );

    res.json({ message: 'Futbolista comprado', precio });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al comprar futbolista' });
  }
});

// vender al futbolista
mercadoRouter.post('/:id_liga/vender/:id_futbolista', verifyToken, async (req, res) => {
  const { id_liga, id_futbolista } = req.params;
  const id_user = req.user.id;

  try {
    // veerifico si es mio o de quien es
    const owned = await db.query(
      `SELECT 1 FROM futbolista_user_liga
       WHERE id_user=$1 AND id_liga=$2 AND id_futbolista=$3`,
      [id_user, id_liga, id_futbolista]
    );

    if (owned.rows.length === 0) {
      return res.status(403).json({ message: 'Este futbolista no es tuyo' });
    }

    // ver el precio del futbolista
    const futbolistaResult = await db.query(
      'SELECT precio FROM futbolistas WHERE id_futbolista = $1',
      [id_futbolista]
    );

    const precio = futbolistaResult.rows[0].precio;

    // elimino al futbolista de mi equipo
    await db.query(
      'DELETE FROM futbolista_user_liga WHERE id_user=$1 AND id_liga=$2 AND id_futbolista=$3',
      [id_user, id_liga, id_futbolista]
    );

    // esto es pa devolver dinero q valia el futbolista
    await db.query(
      'UPDATE users_liga SET dinero = dinero + $1 WHERE id_user=$2 AND id_liga=$3',
      [precio, id_user, id_liga]
    );

    res.json({ message: 'Futbolista vendido', precio });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al vender futbolista' });
  }
});

// ver mis futbolistas
mercadoRouter.get('/:id_liga/mis-futbolistas', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const id_user = req.user.id;

  try {
    const result = await db.query(`
      SELECT f.id_futbolista, f.nombre, f.posicion, f.dorsal, f.precio
      FROM futbolista_user_liga ful
      JOIN futbolistas f ON f.id_futbolista = ful.id_futbolista
      WHERE ful.id_user = $1 AND ful.id_liga = $2
    `, [id_user, id_liga]);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error obteniendo tus futbolistas' });
  }
});

app.use('/api/mercado', mercadoRouter);


// Export para Vercel

module.exports = app;
