const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');
const cors = require('cors');

const app = express();
const secretKey = 'your-secret-key'; // Recuerda cambiar esto en producción por una variable de entorno

const mercadoRouter = express.Router();

app.use(bodyParser.json());

// --- CONFIGURACIÓN CORS ---
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // Responde a preflight OPTIONS
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

// --- MIDDLEWARES DE AUTENTICACIÓN ---

// Verifica si el usuario envía un token válido
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

// Comprueba si el usuario tiene un rol específico dentro de la liga
function requireLeagueRole(roles) {
  return async (req, res, next) => {
    const id_liga = req.params.id_liga || req.body.id_liga;
    if (!id_liga) return res.status(400).json({ message: 'Liga no especificada' });

    try {
      const result = await db.query(
        'SELECT rol FROM users_liga WHERE id_user = $1 AND id_liga = $2',
        [req.user.id, id_liga]
      );

      const rol = result.rows[0]?.rol;
      if (!rol || !roles.includes(rol)) return res.status(403).json({ message: 'No tienes permisos' });

      next();
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Error verificando permisos' });
    }
  };
}

// --- RUTAS PÚBLICAS (AUTH) ---

app.get('/api/data', (req, res) => res.json({ message: 'This is public data' }));

// Registro de usuario
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Todos los campos son obligatorios." });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const avatar = "https://api.dicebear.com/9.x/adventurer-neutral/svg?seed=" + username;

    const result = await db.query(
      "INSERT INTO users (username, email, password, avatar) VALUES ($1,$2,$3,$4) RETURNING id",
      [username, email, hashedPassword, avatar]
    );
    res.status(201).json({ message: "Usuario registrado", userId: result.rows[0].id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al registrar usuario (posiblemente ya existe)." });
  }
});

// Login de usuario
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Username y password requeridos' });

  try {
    const result = await db.query('SELECT * FROM users WHERE username=$1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ message: 'Usuario no existe' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ message: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: user.id, username: user.username, avatar: user.avatar }, secretKey, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error en login' });
  }
});

// Ruta protegida de prueba
app.get('/api/protected', verifyToken, (req, res) => res.json({ message: 'Protected route', user: req.user }));

// --- RUTAS DE PERFIL ---
app.put('/api/perfil', verifyToken, async (req, res) => {
  const { username, avatar } = req.body;
  const userId = req.user.id;

  if (!username || !avatar) return res.status(400).json({ message: 'Datos incompletos' });

  try {
    const checkUser = await db.query('SELECT id FROM users WHERE username = $1 AND id != $2', [username, userId]);
    if (checkUser.rows.length > 0) {
      return res.status(400).json({ message: 'Ese nombre de usuario ya está pillado' });
    }

    await db.query('UPDATE users SET username = $1, avatar = $2 WHERE id = $3', [username, avatar, userId]);

    const newToken = jwt.sign({ id: userId, username: username, avatar: avatar }, secretKey, { expiresIn: '7d' });

    res.json({ message: 'Perfil actualizado con éxito', token: newToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al actualizar el perfil' });
  }
});

// --- RUTAS DE LIGAS ---

const router = express.Router();

// Crear una liga
router.post('/', verifyToken, async (req, res) => {
  let { nombre, clave, max_jugadores } = req.body;
  const idUser = req.user.id;

  if (!nombre || !clave || !max_jugadores) return res.status(400).json({ message: 'Todos los campos son obligatorios' });

  if (max_jugadores > 10) {
    max_jugadores = 10; 
  }

  try {
    // Crear la liga en la tabla de ligas
    const result = await db.query(
      'INSERT INTO ligas (nombre, clave, max_jugadores) VALUES ($1,$2,$3) RETURNING id_liga',
      [nombre, clave, max_jugadores]
    );
    const idLiga = result.rows[0].id_liga;

    // Añadir al creador en users_liga como owner
    await db.query(
      'INSERT INTO users_liga (id_user, id_liga, rol, dinero, puntos) VALUES ($1,$2,$3,$4,$5)',
      [idUser, idLiga, 'owner', 100000000, 0] // 100 Millones iniciales
    );

    // Actualizar el número de jugadores a 1 (El creador)
    await db.query('UPDATE ligas SET numero_jugadores=1 WHERE id_liga=$1', [idLiga]);

    res.status(201).json({ message: 'Liga creada', id_liga: idLiga });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creando liga' });
  }
});

// Obtener ID de liga por nombre y clave
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

// Unirse a una liga 
router.post('/:id_liga/join', verifyToken, async (req, res) => {
  const idUser = req.user.id;
  const { id_liga } = req.params;
  const { clave } = req.body;

  try {
    const ligaResult = await db.query('SELECT * FROM ligas WHERE id_liga=$1', [id_liga]);
    if (!ligaResult.rows[0]) return res.status(404).json({ message: 'Liga no encontrada' });

    const liga = ligaResult.rows[0];
    if (liga.clave !== clave) return res.status(403).json({ message: 'Clave incorrecta' });
    if (liga.numero_jugadores >= liga.max_jugadores) return res.status(403).json({ message: 'Liga llena' });

    // Insertar al usuario como user en la liga
    await db.query('INSERT INTO users_liga (id_user,id_liga,rol,dinero,puntos) VALUES ($1,$2,$3,$4,$5)',
      [idUser, id_liga, 'user', 100000000, 0]
    );

    // Aumentar el número de jugadores
    await db.query('UPDATE ligas SET numero_jugadores = numero_jugadores + 1 WHERE id_liga=$1', [id_liga]);

    res.json({ message: 'Te has unido a la liga', id_liga });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') return res.status(400).json({ message: 'Ya estás en esta liga' });
    res.status(500).json({ message: 'Error al unirse a la liga' });
  }
});

// Eliminar una liga (solo el owner)
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

// Alternar Rol de Admin (Hacer o Quitar Admin) - Solo Owner
router.put('/:id_liga/toggle-admin/:id_user', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
  const { id_liga, id_user } = req.params;
  try {
    const check = await db.query('SELECT rol FROM users_liga WHERE id_user=$1 AND id_liga=$2', [id_user, id_liga]);
    if (check.rows.length === 0) return res.status(404).json({message: 'Usuario no encontrado'});
    if (check.rows[0].rol === 'owner') return res.status(400).json({message: 'No puedes cambiar el rol del Creador'});
    
    // Si es admin lo bajamos a user, si es user lo subimos a admin
    const nuevoRol = check.rows[0].rol === 'admin' ? 'user' : 'admin';
    
    await db.query('UPDATE users_liga SET rol=$1 WHERE id_user=$2 AND id_liga=$3', [nuevoRol, id_user, id_liga]);
    res.json({ message: nuevoRol === 'admin' ? 'Ascendido a Admin ⭐' : 'Relegado a Usuario normal' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al cambiar el rol' });
  }
});

// Vaciar Bandeja de Entrada Privada (Para cualquier usuario)
router.delete('/:id_liga/privados', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const id_user = req.user.id;
  try {
    await db.query('DELETE FROM mensajes_privados WHERE id_liga = $1 AND id_destinatario = $2', [id_liga, id_user]);
    res.json({ message: 'Buzón vaciado con éxito' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al vaciar el buzón' });
  }
});

// Vaciar Chat General (Solo Owner o Admin)
router.delete('/:id_liga/chat', verifyToken, requireLeagueRole(['owner', 'admin']), async (req, res) => {
  const { id_liga } = req.params;
  try {
    await db.query('DELETE FROM chat_general WHERE id_liga = $1', [id_liga]);
    res.json({ message: 'El chat de la liga ha sido borrado' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al borrar el chat' });
  }
});

// Obtener datos del usuario en una liga específica
router.get('/:id_liga/datos-usuario', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const idUser = req.user.id;

  try {
    const result = await db.query(`
      SELECT 
        ul.dinero, 
        ul.puntos, 
        ul.rol,
        ul.formacion,
        (SELECT COALESCE(SUM(monto), 0) FROM pujas 
         WHERE id_user = $1 AND id_liga = $2) as total_pujado,
         
        (SELECT COALESCE(SUM(precio_venta), 0) FROM futbolista_user_liga 
         WHERE id_user = $1 AND id_liga = $2 AND en_venta = true) as total_ventas_esperadas

      FROM users_liga ul 
      WHERE ul.id_user = $1 AND ul.id_liga = $2
    `, [idUser, id_liga]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado en esta liga' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error obteniendo datos del usuario' });
  }
});

// Obtener clasificación de la liga
router.get('/:id_liga/clasificacion', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  try {
    const result = await db.query(`
      SELECT 
        u.id, u.username, u.avatar, ul.puntos, ul.rol,
        (SELECT COUNT(*) FROM futbolista_user_liga ful WHERE ful.id_user = u.id AND ful.id_liga = $1) as total_jugadores
      FROM users_liga ul
      JOIN users u ON ul.id_user = u.id
      WHERE ul.id_liga = $1
      ORDER BY ul.puntos DESC, u.username ASC
    `, [id_liga]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error cargando clasificación' });
  }
});

// Obtener mis jugadores de la liga
router.get('/:id_liga/mis-jugadores', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const idUser = req.user.id;

  try {
    const result = await db.query(`
      SELECT 
        f.id_futbolista, f.nombre, f.posicion, f.precio, f.equipo, f.media,
        f.imagen, f.ataque, f.defensa, f.parada, f.pase,
        f.tipo_carta, f.codigo_habilidad, f.descripcion, -- <--- NUEVOS CAMPOS
        ful.en_venta, ful.precio_venta, ful.es_titular, 
        ful.hueco_plantilla
      FROM futbolista_user_liga ful
      JOIN futbolistas f ON f.id_futbolista = ful.id_futbolista
      WHERE ful.id_liga = $1 AND ful.id_user = $2
      ORDER BY 
        CASE 
          WHEN f.posicion = 'PT' THEN 1
          WHEN f.posicion = 'DF' THEN 2
          WHEN f.posicion = 'MC' THEN 3
          WHEN f.posicion = 'DL' THEN 4
          ELSE 5
        END
    `, [id_liga, idUser]);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error obteniendo tus jugadores' });
  }
});

// Guardar la alineación de un usuario en una liga
router.put('/:id_liga/plantilla', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const idUser = req.user.id;
  const { formacion, titulares } = req.body; 

  try {
    await db.query('BEGIN'); 

    // 1. Actualizar la formación preferida del usuario en esta liga
    if (formacion) {
      await db.query(
        'UPDATE users_liga SET formacion = $1 WHERE id_user = $2 AND id_liga = $3',
        [formacion, idUser, id_liga]
      );
    }

    // 2. Mandar a TODOS los jugadores al banquillo y limpiar su hueco
    await db.query(
      'UPDATE futbolista_user_liga SET es_titular = false, hueco_plantilla = NULL WHERE id_user = $1 AND id_liga = $2',
      [idUser, id_liga]
    );

    // 3. Ascender a titulares a los que estén en el césped en su hueco específico
    if (titulares && titulares.length > 0) {
      for (const tit of titulares) {
        await db.query(
          'UPDATE futbolista_user_liga SET es_titular = true, hueco_plantilla = $1 WHERE id_user = $2 AND id_liga = $3 AND id_futbolista = $4',
          [tit.hueco, idUser, id_liga, tit.id]
        );
      }
    }

    await db.query('COMMIT');
    res.json({ message: '¡Plantilla guardada con éxito!' });
  } catch (err) {
    await db.query('ROLLBACK');
    console.error("Error guardando plantilla:", err);
    res.status(500).json({ message: 'Error al guardar la alineación' });
  }
});

// Guardar la alineación de un usuario en una liga
router.put('/:id_liga/plantilla', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const idUser = req.user.id;
  const { formacion, titulares } = req.body; 

  try {
    await db.query('BEGIN'); 

    // 1. Actualizar la formación preferida del usuario en esta liga
    if (formacion) {
      await db.query(
        'UPDATE users_liga SET formacion = $1 WHERE id_user = $2 AND id_liga = $3',
        [formacion, idUser, id_liga]
      );
    }

    // 2. Mandar a TODOS los jugadores al banquillo y limpiar su hueco
    await db.query(
      'UPDATE futbolista_user_liga SET es_titular = false, hueco_plantilla = NULL WHERE id_user = $1 AND id_liga = $2',
      [idUser, id_liga]
    );

    // 3. Ascender a titulares a los que estén en el césped en su hueco específico
    if (titulares && titulares.length > 0) {
      for (const tit of titulares) {
        
        // --- SEGURIDAD ANTI-HACKERS PARA EL JUGADOR 12 ---
        if (tit.hueco === 'hueco-12') {
          const checkUltra = await db.query(
            'SELECT tipo_carta FROM futbolistas WHERE id_futbolista = $1',
            [tit.id]
          );
          
          if (checkUltra.rows.length === 0 || checkUltra.rows[0].tipo_carta !== 'ultra') {
            throw new Error('Manipulación detectada: El pedestal del Jugador 12 solo admite leyendas ULTRA.');
          }
        }
        // -------------------------------------------------

        await db.query(
          'UPDATE futbolista_user_liga SET es_titular = true, hueco_plantilla = $1 WHERE id_user = $2 AND id_liga = $3 AND id_futbolista = $4',
          [tit.hueco, idUser, id_liga, tit.id]
        );
      }
    }

    await db.query('COMMIT');
    res.json({ message: '¡Plantilla guardada con éxito!' });
    
  } catch (err) {
    await db.query('ROLLBACK');
    console.error("Error guardando plantilla:", err);
    // Devolvemos el mensaje de error específico si alguien intentó la trampa
    res.status(500).json({ message: err.message || 'Error al guardar la alineación' });
  }
});

// Historial de compras y ventas de la liga
router.get('/:id_liga/historial', verifyToken, async (req, res) => {
  const { id_liga } = req.params;

  try {
    const result = await db.query(`
      SELECT 
        h.id_historial,
        h.tipo,
        h.monto,
        h.fecha,
        u1.username AS comprador,
        u2.username AS vendedor,
        f.nombre AS jugador
      FROM historial_transferencias h
      LEFT JOIN users u1 ON h.id_comprador = u1.id
      LEFT JOIN users u2 ON h.id_vendedor = u2.id
      JOIN futbolistas f ON h.id_futbolista = f.id_futbolista
      WHERE h.id_liga = $1
      ORDER BY h.fecha DESC
    `, [id_liga]);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error cargando historial' });
  }
});


// Poner un jugador en venta (Desde ListaJugadores)
router.post('/:id_liga/vender', verifyToken, async (req, res) => {
  const { id_futbolista, precio_venta } = req.body;
  const { id_liga } = req.params;

  try {
    await db.query(
      `UPDATE futbolista_user_liga SET en_venta = true, precio_venta = $1 
       WHERE id_user = $2 AND id_liga = $3 AND id_futbolista = $4`,
      [precio_venta, req.user.id, id_liga, id_futbolista]
    );
    res.json({ message: 'Jugador puesto en venta' });
  } catch (err) {
    res.status(500).json({ message: 'Error al poner en venta' });
  }
});

// Cancelar la venta de un jugador
router.post('/:id_liga/cancelar-venta', verifyToken, async (req, res) => {
  const { id_futbolista } = req.body;
  const { id_liga } = req.params;

  try {
    await db.query(
      `UPDATE futbolista_user_liga SET en_venta = false, precio_venta = 0 
       WHERE id_user = $1 AND id_liga = $2 AND id_futbolista = $3`,
      [req.user.id, id_liga, id_futbolista]
    );
    res.json({ message: 'Venta cancelada' });
  } catch (err) {
    res.status(500).json({ message: 'Error al cancelar la venta' });
  }
});


//CALENDARIO
// Generar el calendario de la liga
router.post('/:id_liga/generar-calendario', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
  const { id_liga } = req.params;

  try {
    await db.query('BEGIN'); // Transacción segura

    // 1. Comprobar si ya hay partidos generados
    const checkPartidos = await db.query('SELECT id_partido FROM partidos WHERE id_liga = $1 LIMIT 1', [id_liga]);
    if (checkPartidos.rows.length > 0) {
      throw new Error('La liga ya tiene un calendario generado.');
    }

    // 2. Extraer TODOS los equipos únicos EXCEPTO el 'Real Trébol FC'
    const teamsRes = await db.query("SELECT DISTINCT equipo FROM futbolistas WHERE equipo != 'Real Trébol FC'");
    let equipos = teamsRes.rows.map(row => row.equipo);

    if (equipos.length < 2) {
      throw new Error('No hay suficientes equipos en la base de datos.');
    }

    if (equipos.length % 2 !== 0) {
      equipos.push('DESCANSA'); 
    }

    const totalEquipos = equipos.length;
    const totalJornadasIda = totalEquipos - 1;
    const partidosPorJornada = totalEquipos / 2;
    let calendario = [];

    // 3. ALGORITMO ROUND-ROBIN (Ida y Vuelta)
    let equiposRotatorios = [...equipos];
    const equipoFijo = equiposRotatorios.shift(); 

    // --- IDA ---
    for (let jornada = 1; jornada <= totalJornadasIda; jornada++) {
      const rivalDelFijo = equiposRotatorios[equiposRotatorios.length - 1];
      if (jornada % 2 === 0) calendario.push({ jornada, local: equipoFijo, visitante: rivalDelFijo });
      else calendario.push({ jornada, local: rivalDelFijo, visitante: equipoFijo });

      for (let i = 0; i < partidosPorJornada - 1; i++) {
        calendario.push({ jornada, local: equiposRotatorios[i], visitante: equiposRotatorios[equiposRotatorios.length - 2 - i] });
      }
      equiposRotatorios.unshift(equiposRotatorios.pop());
    }

    // --- VUELTA ---
    for (let jornada = 1; jornada <= totalJornadasIda; jornada++) {
      const jornadaVuelta = jornada + totalJornadasIda;
      const partidosIda = calendario.filter(p => p.jornada === jornada);
      for (const p of partidosIda) {
        calendario.push({ jornada: jornadaVuelta, local: p.visitante, visitante: p.local });
      }
    }

    // =======================================================
    // 4. EL REPARTO TELEVISIVO (Fechas, Horas y Descansos)
    // =======================================================
    
    // Empieza exactamente en 1 semana (7 días)
    let currentDate = new Date();
    currentDate.setDate(currentDate.getDate() + 7); 
    currentDate.setHours(0, 0, 0, 0);

    const timeSlots = [
      { h: 10, m: 0 }, // Mañana
      { h: 13, m: 0 }, // Mediodía
      { h: 17, m: 0 }, // Tarde
      { h: 20, m: 0 }  // Noche
    ];

    // Función para barajar los horarios al azar
    function shuffle(array) {
      for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
      }
      return array;
    }

    const totalJornadas = totalJornadasIda * 2;

    for (let jornada = 1; jornada <= totalJornadas; jornada++) {
      // Filtramos los partidos reales de esta jornada (ignoramos si alguien "Descansa")
      let partidosJornada = calendario.filter(p => p.jornada === jornada && p.local !== 'DESCANSA' && p.visitante !== 'DESCANSA');
      
      // Reparto de los 10 partidos en 3 días: 3 el Día 1, 3 el Día 2, 4 el Día 3
      const distribucion = [3, 3, 4];
      let partidoIndex = 0;

      for (let dayOffset = 0; dayOffset < 3; dayOffset++) {
        const partidosHoy = distribucion[dayOffset];
        
        // Cogemos horarios al azar (si hoy hay 3 partidos, coge 3 horarios distintos)
        const slotsHoy = shuffle([...timeSlots]).slice(0, partidosHoy);
        
        for (let i = 0; i < partidosHoy; i++) {
          if (partidoIndex < partidosJornada.length) {
            const partido = partidosJornada[partidoIndex];
            
            // Asignamos el día (+0, +1 o +2 días desde el inicio de la jornada) y la hora
            const fechaPartido = new Date(currentDate);
            fechaPartido.setDate(fechaPartido.getDate() + dayOffset);
            fechaPartido.setHours(slotsHoy[i].h, slotsHoy[i].m, 0, 0);

            await db.query(`
              INSERT INTO partidos (id_liga, jornada, equipo_local, equipo_visitante, fecha_partido, estado)
              VALUES ($1, $2, $3, $4, $5, 'pendiente')
            `, [id_liga, partido.jornada, partido.local, partido.visitante, fechaPartido]);

            partidoIndex++;
          }
        }
      }

      // Los partidos se han jugado en el Día 1, Día 2 y Día 3.
      // Añadimos exactamente 2 días de descanso (Día 4 y Día 5 sin fútbol).
      // Por tanto, la siguiente jornada empezará exactamente 5 días después.
      currentDate.setDate(currentDate.getDate() + 5); 
    }

    await db.query('COMMIT');
    res.json({ message: '¡Calendario generado! Pretemporada de 7 días iniciada. 📅⚽' });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error("Error generando calendario:", err);
    res.status(400).json({ message: err.message || 'Error al generar el calendario' });
  }
});

// Obtener el calendario completo de la liga
router.get('/:id_liga/calendario', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  try {
    const result = await db.query(`
      SELECT 
        id_partido, jornada, equipo_local, equipo_visitante, 
        goles_local, goles_visitante, fecha_partido, estado
      FROM partidos
      WHERE id_liga = $1
      ORDER BY fecha_partido ASC
    `, [id_liga]);
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error cargando el calendario' });
  }
});

// Obtener detalles, eventos y ALINEACIONES POPULADAS de un partido concreto
router.get('/:id_liga/partido/:id_partido', verifyToken, async (req, res) => {
  const { id_liga, id_partido } = req.params;
  try {
    const partidoRes = await db.query('SELECT * FROM partidos WHERE id_partido = $1 AND id_liga = $2', [id_partido, id_liga]);
    if(partidoRes.rows.length === 0) return res.status(404).json({message: 'Partido no encontrado'});
    
    const partido = partidoRes.rows[0];

    const eventosRes = await db.query(`
      SELECT e.*, f.nombre as jugador_nombre, f.equipo as equipo_jugador, a.nombre as asistente_nombre
      FROM eventos_partido e
      LEFT JOIN futbolistas f ON e.id_futbolista = f.id_futbolista
      LEFT JOIN futbolistas a ON e.id_asistente = a.id_futbolista
      WHERE e.id_partido = $1
      ORDER BY e.minuto ASC
    `, [id_partido]);

    // Extraer datos de los jugadores de la alineación
    let jugadoresData = [];
    if (partido.alineaciones && partido.alineaciones.local) {
      const ids = [
        ...partido.alineaciones.local.titulares, ...partido.alineaciones.local.banquillo,
        ...partido.alineaciones.visitante.titulares, ...partido.alineaciones.visitante.banquillo
      ];
      if (ids.length > 0) {
        const jRes = await db.query(`
          SELECT id_futbolista, nombre, posicion, media, tipo_carta 
          FROM futbolistas WHERE id_futbolista = ANY($1::int[])
        `, [ids]);
        jugadoresData = jRes.rows;
      }
    }

    res.json({ partido, eventos: eventosRes.rows, jugadores: jugadoresData });
  } catch(err) {
    console.error(err);
    res.status(500).json({message: 'Error cargando detalles del partido'});
  }
});

// 🏆 Obtener el Ranking de Mánagers de UNA jornada específica
router.get('/:id_liga/ranking-jornada/:jornada', verifyToken, async (req, res) => {
  const { id_liga, jornada } = req.params;
  try {
    const query = `
      SELECT 
        u.id, u.username, u.avatar,
        COALESCE(SUM(rp.puntos_totales), 0) as puntos_jornada
      FROM users_liga ul
      JOIN users u ON ul.id_user = u.id
      LEFT JOIN rendimiento_partido rp ON rp.id_user = ul.id_user 
      LEFT JOIN partidos p ON rp.id_partido = p.id_partido AND p.jornada = $2
      WHERE ul.id_liga = $1
      GROUP BY u.id, u.username, u.avatar
      ORDER BY puntos_jornada DESC, u.username ASC
    `;
    const result = await db.query(query, [id_liga, jornada]);
    res.json(result.rows);
  } catch(err) {
    res.status(500).json({message: 'Error cargando ranking de jornada'});
  }
});

// Obtener el Roster y Lore de un equipo de la IA
router.get('/:id_liga/club/:nombre_club', verifyToken, async (req, res) => {
  const { id_liga, nombre_club } = req.params;
  try {
    const jugRes = await db.query(`
      SELECT id_futbolista, nombre, posicion, media, tipo_carta, precio 
      FROM futbolistas WHERE equipo = $1 
      ORDER BY media DESC
    `, [nombre_club]);

    // Generamos un lore dinámico básico (puedes ampliarlo luego en BD si quieres)
    const lores = {
      'Real Trébol FC': 'Los Dioses fundadores de la liga. Invencibles en su estadio.',
      'Motor Club Chacón': 'Velocidad, gasolina y rock n roll. Su ataque es temible.',
      'Athletic Hullera': 'Mineros duros de roer. Su defensa es un muro de piedra.',
      'Deportivo Relámpago': 'El equipo del pueblo, conocido por sus contraataques fugaces.',
      'Real Pinar FC': 'Los reyes del bosque. Fútbol elegante y de toque.'
    };

    res.json({
      equipo: nombre_club,
      lore: lores[nombre_club] || 'Un club histórico de Isla Trébol con una afición muy fiel y pasional.',
      plantilla: jugRes.rows
    });
  } catch(err) {
    res.status(500).json({message: 'Error cargando el club'});
  }
});

app.use('/api/ligas', router);

// Ver ligas de un usuario
app.get('/api/mis-ligas', verifyToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT l.id_liga, l.nombre, l.numero_jugadores, l.max_jugadores, ul.dinero, ul.puntos, ul.rol
       FROM users_liga ul
       JOIN ligas l ON l.id_liga=ul.id_liga
       WHERE ul.id_user=$1`, [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error obteniendo ligas' });
  }
});


// --- RUTAS DE MERCADO  ---
mercadoRouter.get('/:id_liga', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const idUser = req.user.id;

  try {
    const mercadoActual = await db.query(`
      SELECT fecha_generacion FROM mercado_liga WHERE id_liga = $1 LIMIT 1
    `, [id_liga]);

    const mercado = await db.query(`
      -- PARTE 1: JUGADORES DE LA BANCA (Filtrando al Real Trébol)
      SELECT 
        f.id_futbolista, f.nombre, f.posicion, f.equipo, f.media, f.precio as precio, 
        NULL::int as id_vendedor, NULL::text as vendedor_name,
        CASE WHEN p.id_user IS NOT NULL THEN true ELSE false END as pujado_por_mi,
        COALESCE(p.monto, 0) as mi_puja_actual,
        f.imagen, f.ataque, f.defensa, f.parada, f.pase,
        f.tipo_carta, f.codigo_habilidad, f.descripcion
      FROM mercado_liga ml
      JOIN futbolistas f ON f.id_futbolista = ml.id_futbolista
      LEFT JOIN pujas p ON p.id_futbolista = f.id_futbolista AND p.id_liga = $1 AND p.id_user = $2
      WHERE ml.id_liga = $1 
        AND f.equipo != 'Real Trébol FC' -- <--- Veto a los dioses en la banca

      UNION

      -- PARTE 2: JUGADORES DE OTROS USUARIOS (Filtrando al Real Trébol)
      SELECT 
        f.id_futbolista, f.nombre, f.posicion, f.equipo, f.media, ful.precio_venta as precio, 
        ful.id_user as id_vendedor, u.username as vendedor_name, false as pujado_por_mi, 0 as mi_puja_actual,
        f.imagen, f.ataque, f.defensa, f.parada, f.pase,
        f.tipo_carta, f.codigo_habilidad, f.descripcion
      FROM futbolista_user_liga ful
      JOIN futbolistas f ON f.id_futbolista = ful.id_futbolista
      JOIN users u ON u.id = ful.id_user
      WHERE ful.id_liga = $1 
        AND ful.en_venta = true 
        AND f.equipo != 'Real Trébol FC' -- <--- Veto a los dioses en ventas de usuarios
    `, [id_liga, idUser]);

    const fechaGen = mercadoActual.rows.length ? mercadoActual.rows[0].fecha_generacion : new Date();

    res.json({
      jugadores: mercado.rows,
      fecha_generacion: fechaGen
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error obteniendo mercado' });
  }
});

// Realizar una puja por un jugador del mercado
mercadoRouter.post('/pujar', verifyToken, async (req, res) => {
  const { id_liga, id_futbolista, monto } = req.body;
  const idUser = req.user.id;

  if (!id_liga || !id_futbolista || !monto) {
    return res.status(400).json({ message: 'Datos incompletos' });
  }

  try {
    const checkMercado = await db.query(
      'SELECT * FROM mercado_liga WHERE id_liga = $1 AND id_futbolista = $2',
      [id_liga, id_futbolista]
    );
    if (checkMercado.rows.length === 0) {
      return res.status(404).json({ message: 'El jugador no está en el mercado' });
    }

    const jugadorInfo = await db.query('SELECT precio, nombre FROM futbolistas WHERE id_futbolista = $1', [id_futbolista]);
    const precioBase = Number(jugadorInfo.rows[0].precio);

    if (monto < precioBase) {
      return res.status(400).json({ message: `La puja debe ser al menos el valor de mercado (${precioBase})` });
    }

    const userInfo = await db.query(
      'SELECT dinero FROM users_liga WHERE id_user = $1 AND id_liga = $2',
      [idUser, id_liga]
    );
    
    if (Number(userInfo.rows[0].dinero) < monto) {
      return res.status(400).json({ message: 'No tienes suficiente dinero para esta puja' });
    }

    await db.query(
      'DELETE FROM pujas WHERE id_liga = $1 AND id_futbolista = $2 AND id_user = $3',
      [id_liga, id_futbolista, idUser]
    );

    await db.query(
      'INSERT INTO pujas (id_liga, id_futbolista, id_user, monto, fecha) VALUES ($1, $2, $3, $4, NOW())',
      [id_liga, id_futbolista, idUser, monto]
    );

    res.json({ message: `Puja realizada por ${jugadorInfo.rows[0].nombre}` });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al realizar la puja' });
  }
});

// Retirar una puja
mercadoRouter.delete('/pujar', verifyToken, async (req, res) => {
  const { id_liga, id_futbolista } = req.body; 
  const idUser = req.user.id;

  try {
    await db.query(
      'DELETE FROM pujas WHERE id_liga = $1 AND id_futbolista = $2 AND id_user = $3',
      [id_liga, id_futbolista, idUser]
    );
    res.json({ message: 'Puja retirada correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al retirar la puja' });
  }
});

// Comprar jugador directamente a otro usuario (Desde Mercado)
mercadoRouter.post('/compra-directa', verifyToken, async (req, res) => {
  const { id_liga, id_futbolista, id_vendedor, precio } = req.body;
  const idComprador = req.user.id;

  try {
    await db.query('UPDATE users_liga SET dinero = dinero - $1 WHERE id_user = $2 AND id_liga = $3', [precio, idComprador, id_liga]);
    await db.query('UPDATE users_liga SET dinero = dinero + $1 WHERE id_user = $2 AND id_liga = $3', [precio, id_vendedor, id_liga]);

    await db.query(
      `UPDATE futbolista_user_liga SET id_user = $1, en_venta = false, precio_venta = 0 
       WHERE id_user = $2 AND id_liga = $3 AND id_futbolista = $4`,
      [idComprador, id_vendedor, id_liga, id_futbolista]
    );

    await db.query(
      `INSERT INTO historial_transferencias (id_liga, id_futbolista, id_vendedor, id_comprador, monto, tipo)
       VALUES ($1, $2, $3, $4, $5, 'compra_usuario')`,
      [id_liga, id_futbolista, id_vendedor, idComprador, precio]
    );

    res.json({ message: 'Fichaje realizado con éxito' });
  } catch (err) {
    res.status(500).json({ message: 'Error en la transacción' });
  }
});


// SOBRES
// Abrir sobre NORMAL 
router.post('/:id_liga/tienda/abrir-normal', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const id_user = req.user.id;
  const precioSobre = 5000000; // 5 Millones

  try {
    await db.query('BEGIN'); // Empezamos transacción segura

    // 1. Comprobamos si tiene dinero
    const userRes = await db.query('SELECT dinero FROM users_liga WHERE id_liga = $1 AND id_user = $2', [id_liga, id_user]);
    if (userRes.rows.length === 0 || Number(userRes.rows[0].dinero) < precioSobre) {
      throw new Error('No tienes suficientes Tc para este sobre.');
    }

    // 2. Tiramos los dados de la probabilidad (0 a 100)
    const tirada = Math.random() * 100;
    let minMedia = 0;
    let maxMedia = 99;

    if (tirada < 60) { // 60% Bronce
      minMedia = 60; maxMedia = 69;
    } else if (tirada < 85) { // 25% Plata
      minMedia = 70; maxMedia = 79;
    } else if (tirada < 98) { // 13% Oro
      minMedia = 80; maxMedia = 89;
    } else { // 2% Diamante (¡Panelazo!)
      minMedia = 90; maxMedia = 95;
    }

    // 3. Buscamos un jugador aleatorio en ese rango de media QUE ESTÉ LIBRE 
    // ¡Añadido: Que no lo tenga nadie (futbolista_user_liga) NI esté en el mercado (mercado_liga)!
    let jugadorRes = await db.query(`
      SELECT * FROM futbolistas 
      WHERE media >= $1 AND media <= $2 
      AND tipo_carta = 'normal'
      AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $3)
      AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $3)
      ORDER BY RANDOM() LIMIT 1
    `, [minMedia, maxMedia, id_liga]);

    // 4. Sistema de seguridad: ¿Qué pasa si ya no quedan libres de esa categoría? 
    if (jugadorRes.rows.length === 0) {
      jugadorRes = await db.query(`
        SELECT * FROM futbolistas 
        WHERE id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $1)
        AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $1)
        ORDER BY RANDOM() LIMIT 1
      `, [id_liga]);
      
      if (jugadorRes.rows.length === 0) {
        throw new Error('¡Ya no quedan jugadores libres en esta liga!');
      }
    }

    const jugadorTocado = jugadorRes.rows[0];

    // 5. Cobramos el dinero
    await db.query('UPDATE users_liga SET dinero = dinero - $1 WHERE id_liga = $2 AND id_user = $3', [precioSobre, id_liga, id_user]);

    // 6. Le damos el jugador
    await db.query('INSERT INTO futbolista_user_liga (id_user, id_liga, id_futbolista, en_venta, precio_venta) VALUES ($1, $2, $3, false, 0)', 
      [id_user, id_liga, jugadorTocado.id_futbolista]);

    await db.query('COMMIT'); // Guardamos los cambios
    
    // 7. Devolvemos el jugador para la animación
    res.json({ mensaje: 'Sobre abierto con éxito', jugador: jugadorTocado });

  } catch (err) {
    await db.query('ROLLBACK'); // Si algo falla, cancelamos todo para que no pierda dinero
    console.error("Error abriendo sobre:", err);
    res.status(400).json({ message: err.message || 'Error al abrir el sobre.' });
  }
});

// Abrir sobre de posición
router.post('/:id_liga/tienda/abrir-posicion', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const { posicion } = req.body; 
  const id_user = req.user.id;
  const precioSobre = 10000000;

  if (!posicion) return res.status(400).json({ message: 'Posición no especificada.' });

  try {
    await db.query('BEGIN'); 

    // 1. Comprobamos si tiene dinero
    const userRes = await db.query('SELECT dinero FROM users_liga WHERE id_liga = $1 AND id_user = $2', [id_liga, id_user]);
    if (userRes.rows.length === 0 || Number(userRes.rows[0].dinero) < precioSobre) {
      throw new Error('No tienes suficientes Tc para este sobre.');
    }

    // 2. Tiramos los dados (Probabilidades MÁS DIFÍCILES que el normal)
    const tirada = Math.random() * 100;
    let minMedia = 0;
    let maxMedia = 99;

    if (tirada < 70) { // 70% Bronce
      minMedia = 60; maxMedia = 69;
    } else if (tirada < 90) { // 20% Plata
      minMedia = 70; maxMedia = 79;
    } else if (tirada < 99) { // 9% Oro
      minMedia = 80; maxMedia = 89;
    } else { // 1% Diamante (Milagro absoluto)
      minMedia = 90; maxMedia = 95;
    }

    // 3. Buscamos el jugador FILTRANDO POR POSICIÓN
    let jugadorRes = await db.query(`
      SELECT * FROM futbolistas 
      WHERE media >= $1 AND media <= $2 
      AND tipo_carta = 'normal'
      AND TRIM(UPPER(posicion)) = $3
      AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $4)
      AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $4)
      ORDER BY RANDOM() LIMIT 1
    `, [minMedia, maxMedia, posicion, id_liga]);

    // 4. Fallback de seguridad: Si no quedan de esa media, le damos cualquiera de ESA POSICIÓN
    if (jugadorRes.rows.length === 0) {
      jugadorRes = await db.query(`
        SELECT * FROM futbolistas 
        WHERE TRIM(UPPER(posicion)) = $1
        AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $2)
        AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $2)
        ORDER BY RANDOM() LIMIT 1
      `, [posicion, id_liga]);
      
      if (jugadorRes.rows.length === 0) {
        throw new Error(`¡Ya no quedan jugadores libres en la posición ${posicion}!`);
      }
    }

    const jugadorTocado = jugadorRes.rows[0];

    // 5. Cobramos los 15 Millones
    await db.query('UPDATE users_liga SET dinero = dinero - $1 WHERE id_liga = $2 AND id_user = $3', [precioSobre, id_liga, id_user]);

    // 6. Damos el jugador
    await db.query('INSERT INTO futbolista_user_liga (id_user, id_liga, id_futbolista, en_venta, precio_venta) VALUES ($1, $2, $3, false, 0)', 
      [id_user, id_liga, jugadorTocado.id_futbolista]);

    await db.query('COMMIT');
    res.json({ mensaje: 'Sobre abierto con éxito', jugador: jugadorTocado });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error("Error abriendo sobre de posición:", err);
    res.status(400).json({ message: err.message || 'Error al abrir el sobre.' });
  }
});

// Abrir Sobre ESPECIAL (Probabilidad de Normal o Especial)
router.post('/:id_liga/tienda/abrir-especial', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const id_user = req.user.id;
  const precioSobre = 20000000; // 20 Millones de Tc

  try {
    await db.query('BEGIN');

    // 1. Validar saldo
    const userRes = await db.query('SELECT dinero FROM users_liga WHERE id_liga = $1 AND id_user = $2', [id_liga, id_user]);
    if (userRes.rows.length === 0 || Number(userRes.rows[0].dinero) < precioSobre) {
      throw new Error('No tienes suficientes Tc. El sobre cuesta 25 Millones.');
    }

    // 2. TIRADA PRINCIPAL: ¿Toca Normal o Especial?
    const esEspecial = (Math.random() * 100) < 20; // 20% de probabilidad de ser Especial

    let minMedia = 0;
    let maxMedia = 99;
    let tipoCarta = esEspecial ? 'especial' : 'normal';

    // 3. TIRADA SECUNDARIA: ¿De qué nivel es dentro de su categoría?
    const tiradaNivel = Math.random() * 100;

    if (esEspecial) {
      // Porcentajes para Cartas ESPECIALES
      if (tiradaNivel < 70) { minMedia = 77; maxMedia = 82; } // 70% Especial Nivel 1
      else if (tiradaNivel < 95) { minMedia = 83; maxMedia = 88; } // 25% Especial Nivel 2
      else { minMedia = 89; maxMedia = 95; } // 5% Especial LEYENDA (MotoChacón)
    } else {
      // Porcentajes MEJORADOS para Cartas NORMALES (Ya que el sobre es caro, evitamos muchos bronces)
      if (tiradaNivel < 40) { minMedia = 60; maxMedia = 69; } // 40% Bronce (antes 60%)
      else if (tiradaNivel < 75) { minMedia = 70; maxMedia = 79; } // 35% Plata (antes 25%)
      else if (tiradaNivel < 95) { minMedia = 80; maxMedia = 89; } // 20% Oro (antes 13%)
      else { minMedia = 90; maxMedia = 95; } // 5% Diamante (antes 2%)
    }

    // 4. Buscar el jugador con esas condiciones que esté LIBRE
    let jugadorRes = await db.query(`
      SELECT * FROM futbolistas 
      WHERE media >= $1 AND media <= $2 
      AND tipo_carta = $3
      AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $4)
      AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $4)
      ORDER BY RANDOM() LIMIT 1
    `, [minMedia, maxMedia, tipoCarta, id_liga]);

    // 5. Fallback por si no quedan jugadores de ese nivel en esa categoría
    if (jugadorRes.rows.length === 0) {
      jugadorRes = await db.query(`
        SELECT * FROM futbolistas 
        WHERE tipo_carta = $1
        AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $2)
        AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $2)
        ORDER BY RANDOM() LIMIT 1
      `, [tipoCarta, id_liga]);
      
      if (jugadorRes.rows.length === 0) {
        throw new Error(`¡Ya no quedan cartas libres de tipo ${tipoCarta} en la liga!`);
      }
    }

    const jugadorTocado = jugadorRes.rows[0];

    // 6. Cobrar los 25 Millones
    await db.query('UPDATE users_liga SET dinero = dinero - $1 WHERE id_liga = $2 AND id_user = $3', [precioSobre, id_liga, id_user]);

    // 7. Entregar el jugador
    await db.query('INSERT INTO futbolista_user_liga (id_user, id_liga, id_futbolista, en_venta, precio_venta) VALUES ($1, $2, $3, false, 0)', 
      [id_user, id_liga, jugadorTocado.id_futbolista]);

    await db.query('COMMIT'); 
    
    // Devolvemos el jugador entero. El frontend leerá "jugador.tipo_carta" para la animación.
    res.json({ mensaje: 'Sobre abierto con éxito', jugador: jugadorTocado });

  } catch (err) {
    await db.query('ROLLBACK'); 
    console.error("Error abriendo sobre especial:", err);
    res.status(400).json({ message: err.message || 'Error al abrir el sobre especial.' });
  }
});

// Abrir sobre ULTRA (EL SOBRE DEFINITIVO)
router.post('/:id_liga/tienda/abrir-ultra', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const id_user = req.user.id;
  const precioSobre = 30000000; // 30 Millones de Tc

  try {
    await db.query('BEGIN'); // Transacción segura

    // 1. Verificar si el usuario tiene la pasta
    const userRes = await db.query(
      'SELECT dinero FROM users_liga WHERE id_liga = $1 AND id_user = $2',
      [id_liga, id_user]
    );

    if (userRes.rows.length === 0 || Number(userRes.rows[0].dinero) < precioSobre) {
      throw new Error('Fondos insuficientes para el Sobre Ultra (30M Tc).');
    }

    // 2. TIRADA DE RAREZA (Probabilidades: 5% Ultra, 25% Especial, 70% Normal)
    const suerte = Math.random() * 100;
    let tipoTocado = 'normal';
    
    if (suerte < 5) {
      tipoTocado = 'ultra'; // ¡Día de suerte!
    } else if (suerte < 30) {
      tipoTocado = 'especial';
    }

    // 3. BUSCAR JUGADOR DISPONIBLE
    // - Si es Ultra, buscamos en el Real Trébol FC.
    // - Si es el resto, buscamos en los otros equipos.
    // - Importante: Que no lo tenga nadie en la liga y no esté en el mercado.
    let queryJugador = `
      SELECT * FROM futbolistas 
      WHERE tipo_carta = $1 
      AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $2)
      AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $2)
    `;

    // Filtro extra por equipo
    if (tipoTocado === 'ultra') {
      queryJugador += " AND equipo = 'Real Trébol FC'";
    } else {
      queryJugador += " AND equipo != 'Real Trébol FC'";
    }

    queryJugador += " ORDER BY RANDOM() LIMIT 1";

    let jugadorRes = await db.query(queryJugador, [tipoTocado, id_liga]);

    // 4. FALLBACK: Si no quedan cartas de esa rareza, bajamos un escalón
    if (jugadorRes.rows.length === 0) {
      jugadorRes = await db.query(`
        SELECT * FROM futbolistas 
        WHERE equipo != 'Real Trébol FC'
        AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $1)
        AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $1)
        ORDER BY media DESC LIMIT 1
      `, [id_liga]);
      
      if (jugadorRes.rows.length === 0) {
        throw new Error('¡Increíble! Ya no quedan jugadores libres en esta liga.');
      }
    }

    const crack = jugadorRes.rows[0];

    // 5. COBRAR Y ENTREGAR
    await db.query(
      'UPDATE users_liga SET dinero = dinero - $1 WHERE id_liga = $2 AND id_user = $3',
      [precioSobre, id_liga, id_user]
    );

    await db.query(
      'INSERT INTO futbolista_user_liga (id_user, id_liga, id_futbolista) VALUES ($1, $2, $3)',
      [id_user, id_liga, crack.id_futbolista]
    );

    // 6. ANUNCIO ÉPICO (Si es Ultra)
    if (crack.tipo_carta === 'ultra') {
      const msj = `👑 ¡HISTÓRICO! @${req.user.username} ha subido al Monte Trébol y ha reclutado a ${crack.nombre} (ULTRA). ¡La isla tiembla!`;
      await db.query(
        'INSERT INTO chat_general (id_liga, id_user, mensaje) VALUES ($1, $2, $3)',
        [id_liga, id_user, msj]
      );
    }

    await db.query('COMMIT');
    res.json({ mensaje: '¡Sobre Ultra procesado!', jugador: crack });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error(err);
    res.status(400).json({ message: err.message });
  }
});


//CENTRO-DE-MENSAJES
// Obtener los mensajes del Chat General de la Liga
router.get('/:id_liga/chat', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  try {
    const result = await db.query(`
      SELECT 
        c.id_mensaje, c.mensaje as texto, c.fecha, 
        u.username as remitente, u.id as id_remitente
      FROM chat_general c
      JOIN users u ON c.id_user = u.id
      WHERE c.id_liga = $1
      ORDER BY c.fecha ASC
      LIMIT 100
    `, [id_liga]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error cargando el chat general' });
  }
});

// Enviar un mensaje al Chat General
router.post('/:id_liga/chat', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const { texto } = req.body;
  const id_user = req.user.id;

  if (!texto || texto.trim() === '') {
    return res.status(400).json({ message: 'El mensaje no puede estar vacío' });
  }

  try {
    await db.query(
      'INSERT INTO chat_general (id_liga, id_user, mensaje) VALUES ($1, $2, $3)',
      [id_liga, id_user, texto]
    );
    res.json({ message: 'Mensaje enviado correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al enviar el mensaje' });
  }
});

// Obtener la Bandeja de Entrada (Mensajes Privados)
router.get('/:id_liga/privados', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const id_user = req.user.id;

  try {
    const result = await db.query(`
      SELECT 
        m.id_privado, m.tipo, m.asunto, m.contenido, m.leido, m.fecha, m.id_oferta, 
        u.username as remitente
      FROM mensajes_privados m
      JOIN users u ON m.id_remitente = u.id
      WHERE m.id_liga = $1 AND m.id_destinatario = $2
      ORDER BY m.fecha DESC
    `, [id_liga, id_user]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error cargando el buzón privado' });
  }
});

// Enviar un Mensaje Normal (Desde la Clasificación)
router.post('/:id_liga/mensajes-texto', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const { id_destinatario, asunto, contenido } = req.body;
  const id_remitente = req.user.id;

  try {
    await db.query(`
      INSERT INTO mensajes_privados (id_liga, id_remitente, id_destinatario, tipo, asunto, contenido)
      VALUES ($1, $2, $3, 'texto', $4, $5)
    `, [id_liga, id_remitente, id_destinatario, asunto, contenido]);
    
    res.json({ message: 'Mensaje enviado correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al enviar el mensaje' });
  }
});

// Enviar una Oferta por un Jugador (Desde Plantilla Rival)
router.post('/:id_liga/ofertas', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const { id_destinatario, id_futbolista, monto } = req.body;
  const id_comprador = req.user.id;

  try {
    // 1. Crear la oferta oficial en la tabla de negociaciones
    const ofertaRes = await db.query(`
      INSERT INTO ofertas_privadas (id_liga, id_futbolista, id_comprador, id_vendedor, monto)
      VALUES ($1, $2, $3, $4, $5) RETURNING id_oferta
    `, [id_liga, id_futbolista, id_comprador, id_destinatario, monto]);
    const id_oferta = ofertaRes.rows[0].id_oferta;

    // 2. Obtener el nombre del jugador para el asunto
    const futRes = await db.query('SELECT nombre FROM futbolistas WHERE id_futbolista = $1', [id_futbolista]);
    const nombreJugador = futRes.rows[0].nombre;

    // 3. Crear el mensaje en el buzón con el formato de oferta
    const asunto = `Oferta por ${nombreJugador}`;
    const contenido = `Te ofrezco ${monto} Tc por tu jugador ${nombreJugador}. ¿Aceptas el trato?`;

    await db.query(`
      INSERT INTO mensajes_privados (id_liga, id_remitente, id_destinatario, tipo, asunto, contenido, id_oferta)
      VALUES ($1, $2, $3, 'oferta', $4, $5, $6)
    `, [id_liga, id_comprador, id_destinatario, asunto, contenido, id_oferta]);

    res.json({ message: 'Oferta enviada. A ver qué responde.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al enviar la oferta' });
  }
});

// ACEPTAR LA OFERTA (Hace el intercambio de jugador y dinero automático)
router.post('/:id_liga/ofertas/aceptar', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const { id_oferta, id_mensaje } = req.body;
  const id_vendedor = req.user.id;

  try {
    await db.query('BEGIN'); // Iniciamos una transacción segura

    // 1. Buscar la oferta y validarla
    const ofertaRes = await db.query("SELECT * FROM ofertas_privadas WHERE id_oferta = $1 AND estado = 'pendiente'", [id_oferta]);
    if (ofertaRes.rows.length === 0) throw new Error('La oferta ya no es válida o ha caducado.');
    const oferta = ofertaRes.rows[0];

    // 2. Comprobar que el comprador tiene dinero (¡Aquí usamos users_liga!)
    const compradorRes = await db.query('SELECT dinero FROM users_liga WHERE id_liga = $1 AND id_user = $2', [id_liga, oferta.id_comprador]);
    if (compradorRes.rows[0].dinero < oferta.monto) throw new Error('El comprador ya no tiene dinero suficiente.');

    // 3. Mover el dinero (¡Y aquí también usamos users_liga!)
    await db.query('UPDATE users_liga SET dinero = dinero - $1 WHERE id_liga = $2 AND id_user = $3', [oferta.monto, id_liga, oferta.id_comprador]);
    await db.query('UPDATE users_liga SET dinero = dinero + $1 WHERE id_liga = $2 AND id_user = $3', [oferta.monto, id_liga, id_vendedor]);

    // 4. Traspasar al jugador
    await db.query(`
      UPDATE futbolista_user_liga 
      SET id_user = $1, en_venta = false, precio_venta = 0 
      WHERE id_futbolista = $2 AND id_liga = $3
    `, [oferta.id_comprador, oferta.id_futbolista, id_liga]);

    // 5. Marcar oferta como aceptada y mensaje como procesado
    await db.query("UPDATE ofertas_privadas SET estado = 'aceptada' WHERE id_oferta = $1", [id_oferta]);
    await db.query("UPDATE mensajes_privados SET leido = true, tipo = 'texto', contenido = contenido || '\n\n✅ OFERTA ACEPTADA' WHERE id_privado = $1", [id_mensaje]);

    // 6. Le mandamos un mensaje automático al comprador diciendo que es suyo
    await db.query(`
      INSERT INTO mensajes_privados (id_liga, id_remitente, id_destinatario, tipo, asunto, contenido)
      VALUES ($1, $2, $3, 'texto', '¡Trato cerrado!', 'Tu oferta de ${oferta.monto} Tc ha sido aceptada. El jugador ya está en tu plantilla.')
    `, [id_liga, id_vendedor, oferta.id_comprador]);

    await db.query('COMMIT'); // Guardamos los cambios
    res.json({ message: '¡Trato cerrado! Dinero y jugador intercambiados.' });
  } catch (err) {
    await db.query('ROLLBACK'); // Si algo falla, cancelamos todo para no perder datos
    console.error("Error al aceptar oferta:", err);
    res.status(400).json({ message: err.message || 'Error al procesar la oferta.' });
  }
});

// Marcar mensaje como leído al abrirlo
router.put('/:id_liga/mensajes/:id_mensaje/leer', verifyToken, async (req, res) => {
  try {
    await db.query('UPDATE mensajes_privados SET leido = true WHERE id_privado = $1', [req.params.id_mensaje]);
    res.json({ message: 'Leído' });
  } catch (err) { res.status(500).json({ message: 'Error' }); }
});

// Rechazar una oferta (o contraofertar si mandas texto)
router.post('/:id_liga/ofertas/rechazar', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const { id_oferta, id_mensaje, motivo } = req.body;
  const id_vendedor = req.user.id;

  try {
    // Marcamos la oferta como rechazada y el mensaje como leído
    await db.query("UPDATE ofertas_privadas SET estado = 'rechazada' WHERE id_oferta = $1", [id_oferta]);
    await db.query("UPDATE mensajes_privados SET leido = true, tipo = 'texto', contenido = contenido || '\n\n❌ OFERTA RECHAZADA' WHERE id_privado = $1", [id_mensaje]);
    
    // Le mandamos un mensaje automático al comprador diciéndole que le han dicho que NO
    const offRes = await db.query("SELECT id_comprador FROM ofertas_privadas WHERE id_oferta = $1", [id_oferta]);
    const id_comprador = offRes.rows[0].id_comprador;

    await db.query(`
      INSERT INTO mensajes_privados (id_liga, id_remitente, id_destinatario, tipo, asunto, contenido)
      VALUES ($1, $2, $3, 'texto', 'Oferta Rechazada', $4)
    `, [id_liga, id_vendedor, id_comprador, `He rechazado tu oferta. ${motivo ? 'Mi respuesta: ' + motivo : 'No me interesa.'}`]);

    res.json({ message: 'Oferta rechazada correctamente.' });
  } catch (err) { res.status(500).json({ message: 'Error al rechazar' }); }
});


app.use('/api/mercado', mercadoRouter);

// CRON JOB: ACTUALIZACIÓN A LAS 00:00 
app.get('/api/cron/medianoche', async (req, res) => {
  
  // Protección para que solo Vercel pueda ejecutar esto leyendo el CRON_SECRET
  const authHeader = req.headers.authorization;
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    console.error("Intento fallido de Cron. Token recibido:", authHeader);
    return res.status(401).json({ error: 'No autorizado' });
  }

  try {
    console.log("Iniciando actualización nocturna del mercado...");
    await db.query('BEGIN'); // Iniciamos transacción segura

    // 1. Buscamos todas las ligas activas
    const ligasRes = await db.query('SELECT id_liga FROM ligas');
    
    for (const liga of ligasRes.rows) {
      const id_liga = liga.id_liga;
      console.log(`Resolviendo pujas para la liga ${id_liga}...`);

      // 2. Obtener todos los jugadores del mercado ACTUAL de esta liga
      const jugadoresEnMercado = await db.query('SELECT id_futbolista FROM mercado_liga WHERE id_liga = $1', [id_liga]);

      // 3. Resolver quién se lleva a cada jugador
      for (const j of jugadoresEnMercado.rows) {
        const idFutbolista = j.id_futbolista;

        // Buscar la puja MÁS ALTA
        const pujaGanadora = await db.query(`
          SELECT * FROM pujas WHERE id_liga = $1 AND id_futbolista = $2 ORDER BY monto DESC LIMIT 1
        `, [id_liga, idFutbolista]);

        if (pujaGanadora.rows.length > 0) {
          const ganador = pujaGanadora.rows[0];
          const idGanador = ganador.id_user;
          const montoPujado = Number(ganador.monto);

          // Verificar si el ganador sigue teniendo dinero
          const saldoGanador = await db.query('SELECT dinero FROM users_liga WHERE id_user = $1 AND id_liga = $2', [idGanador, id_liga]);

          if (saldoGanador.rows.length > 0 && Number(saldoGanador.rows[0].dinero) >= montoPujado) {
            // A) Restar dinero
            await db.query('UPDATE users_liga SET dinero = dinero - $1 WHERE id_user = $2 AND id_liga = $3', [montoPujado, idGanador, id_liga]);
            // B) Dar jugador
            await db.query('INSERT INTO futbolista_user_liga (id_user, id_liga, id_futbolista) VALUES ($1, $2, $3)', [idGanador, id_liga, idFutbolista]);
            // C) Guardar en Historial
            await db.query(`
              INSERT INTO historial_transferencias (id_liga, id_futbolista, id_vendedor, id_comprador, monto, fecha, tipo)
              VALUES ($1, $2, NULL, $3, $4, NOW(), 'compra_mercado')
            `, [id_liga, idFutbolista, idGanador, montoPujado]);
          }
        }
      }

      // ==========================================
      // EL SISTEMA COMPRA JUGADORES SIN VENDER (80% DEL VALOR BASE)
      // ==========================================
      console.log(`El sistema está revisando jugadores en venta de la liga ${id_liga}...`);
      
      const jugadoresEnVenta = await db.query(`
        SELECT ful.id_user, ful.id_futbolista, f.precio
        FROM futbolista_user_liga ful
        JOIN futbolistas f ON ful.id_futbolista = f.id_futbolista
        WHERE ful.id_liga = $1 AND ful.en_venta = true
      `, [id_liga]);

      for (const jv of jugadoresEnVenta.rows) {
        const idVendedor = jv.id_user;
        const idFutbolista = jv.id_futbolista;
        const valorVentaSistema = Math.floor(Number(jv.precio) * 0.8); 

        await db.query('UPDATE users_liga SET dinero = dinero + $1 WHERE id_user = $2 AND id_liga = $3', 
          [valorVentaSistema, idVendedor, id_liga]);

        await db.query('DELETE FROM futbolista_user_liga WHERE id_user = $1 AND id_liga = $2 AND id_futbolista = $3', 
          [idVendedor, id_liga, idFutbolista]);

        await db.query(`
          INSERT INTO historial_transferencias (id_liga, id_futbolista, id_vendedor, id_comprador, monto, fecha, tipo)
          VALUES ($1, $2, $3, NULL, $4, NOW(), 'venta_sistema')
        `, [id_liga, idFutbolista, idVendedor, valorVentaSistema]);

        const futData = await db.query('SELECT nombre FROM futbolistas WHERE id_futbolista = $1', [idFutbolista]);
        const nombreJugadorVendido = futData.rows[0]?.nombre || 'un jugador';

        const ownerRes = await db.query("SELECT id_user FROM users_liga WHERE id_liga = $1 AND rol = 'owner' LIMIT 1", [id_liga]);
        const idPresidente = ownerRes.rows.length > 0 ? ownerRes.rows[0].id_user : idVendedor;

        await db.query(`
          INSERT INTO mensajes_privados (id_liga, id_remitente, id_destinatario, tipo, asunto, contenido)
          VALUES ($1, $2, $3, 'texto', '💸 Venta al Sistema', $4)
        `, [
          id_liga, 
          idPresidente, 
          idVendedor,
          `El mercado ha cerrado y nadie ha pujado por él. El sistema ha comprado a tu jugador ${nombreJugadorVendido} por el 80% de su valor base (${valorVentaSistema} Tc). El dinero ya ha sido ingresado en tu cuenta y el jugador vuelve a estar en los sobres.`
        ]);
      }

      // 4. Limpiar el mercado viejo y las pujas de ayer de ESTA liga
      await db.query('DELETE FROM pujas WHERE id_liga = $1', [id_liga]);
      await db.query('DELETE FROM mercado_liga WHERE id_liga = $1', [id_liga]);

      // 5. Generar los 20 NUEVOS jugadores asegurando 3 de cada posición
      const nuevosJugadores = await db.query(`
        WITH Disponibles AS (
          SELECT id_futbolista, TRIM(UPPER(posicion)) as pos_limpia,
                 ROW_NUMBER() OVER(PARTITION BY TRIM(UPPER(posicion)) ORDER BY RANDOM()) as rn,
                 RANDOM() as rnd
          FROM futbolistas 
          WHERE equipo != 'Real Trébol FC' 
            AND tipo_carta = 'normal' -- <--- ¡FIX! Solo jugadores normales al mercado
            AND id_futbolista NOT IN (
            SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $1
          )
        )
        SELECT id_futbolista 
        FROM Disponibles 
        ORDER BY CASE WHEN rn <= 3 THEN 0 ELSE 1 END, rnd
        LIMIT 20
      `, [id_liga]);

      for (const j of nuevosJugadores.rows) {
        await db.query('INSERT INTO mercado_liga (id_liga, id_futbolista, fecha_generacion) VALUES ($1, $2, NOW())', [id_liga, j.id_futbolista]);
      }
    }

    await db.query('COMMIT');
    console.log("¡Mercado nocturno actualizado con éxito!");
    res.json({ message: 'Mercado actualizado correctamente.' });
  } catch (err) {
    await db.query('ROLLBACK');
    console.error("Error en CRON nocturno:", err);
    res.status(500).json({ error: 'Fallo al actualizar el mercado' });
  }
});

// ==========================================
// 🧠 CEREBRO DE LA IA: ESTILOS DE JUEGO Y FORMACIONES
// ==========================================
const CONFIG_EQUIPOS_IA = {
  'Real Pinar FC': { formacion: '4-3-3' }, 'Neón City FC': { formacion: '4-3-3' },
  'Pixel United': { formacion: '4-3-3' }, 'CF Átomo': { formacion: '4-3-3' },
  'Club Náutico Brisamar': { formacion: '4-4-2' }, 'Racing Vaguadas': { formacion: '4-4-2' },
  'UD Recreo': { formacion: '4-4-2' }, 'Alianza Metropolitana': { formacion: '4-4-2' },
  'Deportivo Relámpago': { formacion: '3-5-2' }, 'Gourmet FC': { formacion: '3-5-2' },
  'Cosmos United': { formacion: '3-5-2' }, 'Motor Club Chacón': { formacion: '3-4-3' },
  'Dragones de Oriente': { formacion: '3-4-3' }, 'Real Trébol FC': { formacion: '3-4-3' },
  'Athletic Hullera': { formacion: '5-4-1' }, 'CD Refugio': { formacion: '5-4-1' },
  'Unión Fortaleza': { formacion: '5-4-1' }, 'CD Frontera': { formacion: '5-3-2' },
  'Sporting Lechuza': { formacion: '5-3-2' }, 'Titanes CF': { formacion: '5-3-2' },
  'Pangea FC': { formacion: '5-3-2' }
};

const REQ_FORMACION = {
  '4-3-3': { PT: 1, DF: 4, MC: 3, DL: 3 }, '4-4-2': { PT: 1, DF: 4, MC: 4, DL: 2 },
  '3-5-2': { PT: 1, DF: 3, MC: 5, DL: 2 }, '3-4-3': { PT: 1, DF: 3, MC: 4, DL: 3 },
  '5-4-1': { PT: 1, DF: 5, MC: 4, DL: 1 }, '5-3-2': { PT: 1, DF: 5, MC: 3, DL: 2 }
};

// =================================================================
// 🎮 CRON JOB: MOTOR DE SIMULACIÓN DE PARTIDOS V3 (70 MINUTOS + MAGIA)
// =================================================================
app.get('/api/cron/simular-partidos', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) return res.status(401).json({ error: 'No autorizado' });

  try {
    const partidosRes = await db.query(`SELECT * FROM partidos WHERE estado = 'pendiente' AND fecha_partido <= NOW()`);
    if (partidosRes.rows.length === 0) return res.json({ message: 'No hay partidos pendientes.' });

    // Restamos 1 partido de sanción y lesión a TODOS los jugadores de la base de datos
    await db.query(`UPDATE futbolistas SET partidos_sancion = GREATEST(0, partidos_sancion - 1), partidos_lesion = GREATEST(0, partidos_lesion - 1)`);

    for (const partido of partidosRes.rows) {
      await db.query('BEGIN');
      
      // 1. Cargar disponibles (Ni lesionados, ni sancionados)
      const jugRes = await db.query(`SELECT * FROM futbolistas WHERE equipo IN ($1, $2) AND partidos_lesion = 0 AND partidos_sancion = 0`, [partido.equipo_local, partido.equipo_visitante]);

      const armarEquipo = (nombreEquipo) => {
        const plantilla = jugRes.rows.filter(j => j.equipo === nombreEquipo).sort((a, b) => ((b.media * 0.7) + (b.forma_actual * 3)) - ((a.media * 0.7) + (a.forma_actual * 3)));
        const formacion = CONFIG_EQUIPOS_IA[nombreEquipo]?.formacion || '4-4-2';
        const reqs = { ...REQ_FORMACION[formacion] };
        
        let titulares = []; let banquillo = []; let onPitch = { PT: 0, DF: 0, MC: 0, DL: 0 };
        plantilla.forEach(j => {
          let pos = j.posicion.trim().toUpperCase();
          if (pos.includes('DEL')) pos = 'DL'; if (pos.includes('DEF')) pos = 'DF'; if (pos.includes('POR')) pos = 'PT';
          if (onPitch[pos] < reqs[pos]) { titulares.push(j); onPitch[pos]++; } else if (banquillo.length < 7) { banquillo.push(j); }
        });
        return { titulares, banquillo, cambiosHechos: 0, rojas: 0, nombre: nombreEquipo };
      };

      let local = armarEquipo(partido.equipo_local);
      let visit = armarEquipo(partido.equipo_visitante);
      let golesLocal = 0, golesVisit = 0, eventos = [], statsPartido = {}, partidoSuspendido = false;

      // JSON de Alineaciones para mostrar luego en el Frontend
      const alineacionGuardada = {
        local: { equipo: local.nombre, titulares: local.titulares.map(t=>t.id_futbolista), banquillo: local.banquillo.map(b=>b.id_futbolista) },
        visitante: { equipo: visit.nombre, titulares: visit.titulares.map(t=>t.id_futbolista), banquillo: visit.banquillo.map(b=>b.id_futbolista) }
      };

      [...local.titulares, ...local.banquillo, ...visit.titulares, ...visit.banquillo].forEach(j => {
        statsPartido[j.id_futbolista] = { ...j, jugo: false, goles: 0, asistencias: 0, amarillas: 0, rojas: 0, nota_final: null };
      });
      local.titulares.forEach(j => statsPartido[j.id_futbolista].jugo = true);
      visit.titulares.forEach(j => statsPartido[j.id_futbolista].jugo = true);

      // --- 2. EL PARTIDO (70 MINS: 60 JUEGO + 10 DESCANSO) ---
      for (let minuto = 1; minuto <= 70; minuto++) {
        if (partidoSuspendido) break;

        // DESCANSO (Minutos 31 al 40)
        if (minuto > 30 && minuto <= 40) {
          if (minuto === 31) {
            eventos.push({ minuto: 30, tipo_evento: 'info', id_futbolista: null, descripcion: '⏱️ Final de la primera parte. Los jugadores se van al vestuario.' });
            [local, visit].forEach(equipo => {
              if (equipo.banquillo.length > 0 && equipo.cambiosHechos < 5 && Math.random() > 0.2) {
                const sale = equipo.titulares[Math.floor(Math.random() * equipo.titulares.length)];
                const entra = equipo.banquillo.shift();
                equipo.titulares = equipo.titulares.filter(j => j.id_futbolista !== sale.id_futbolista);
                equipo.titulares.push(entra);
                statsPartido[entra.id_futbolista].jugo = true;
                equipo.cambiosHechos++;
                eventos.push({ minuto: 'HT', tipo_evento: 'cambio', id_futbolista: entra.id_futbolista, descripcion: `🔄 Cambio táctico al descanso: Entra ${entra.nombre}, sale ${sale.nombre}.` });
              }
            });
          }
          if (minuto === 40) eventos.push({ minuto: 41, tipo_evento: 'info', id_futbolista: null, descripcion: '⚽ Arranca la segunda mitad.' });
          continue; 
        }

        const minReal = minuto > 40 ? minuto - 10 : minuto;

        // GOLES
        if (Math.random() < 0.06) {
          const atacaLocal = Math.random() < 0.5;
          const atacante = atacaLocal ? local : visit;
          if (atacante.titulares.length > 0) {
            const goleador = atacante.titulares[Math.floor(Math.random() * atacante.titulares.length)];
            let asistente = null;
            if (Math.random() < 0.5 && atacante.titulares.length > 1) {
              asistente = atacante.titulares.filter(j => j.id_futbolista !== goleador.id_futbolista)[0];
              statsPartido[asistente.id_futbolista].asistencias++;
            }
            statsPartido[goleador.id_futbolista].goles++;
            if (atacaLocal) golesLocal++; else golesVisit++;
            eventos.push({ minuto: minReal, tipo_evento: 'gol', id_futbolista: goleador.id_futbolista, descripcion: `¡GOOOOL de ${goleador.nombre}!` });
          }
        }

        // LESIONES (1% chance)
        if (Math.random() < 0.01) {
          const sufreLesion = Math.random() < 0.5 ? local : visit;
          if (sufreLesion.titulares.length > 0) {
            const lesionado = sufreLesion.titulares[Math.floor(Math.random() * sufreLesion.titulares.length)];
            sufreLesion.titulares = sufreLesion.titulares.filter(j => j.id_futbolista !== lesionado.id_futbolista);
            const tirada = Math.random();
            let dias = 1, tipo = 'Sobrecarga muscular';
            if (tirada > 0.9) { dias = 14; tipo = 'Rotura de ligamentos'; } else if (tirada > 0.7) { dias = 7; tipo = 'Rotura fibrilar'; } else if (tirada > 0.4) { dias = 3; tipo = 'Esguince de tobillo'; }
            statsPartido[lesionado.id_futbolista].lesion_sufrida = { dias, tipo };
            let desc = `🚑 ¡LESIÓN! ${lesionado.nombre} se retira en camilla (${tipo}).`;
            if (sufreLesion.banquillo.length > 0) {
              const entra = sufreLesion.banquillo.shift();
              sufreLesion.titulares.push(entra);
              statsPartido[entra.id_futbolista].jugo = true;
              desc += ` Entra ${entra.nombre}.`;
            } else { desc += ` ¡Se quedan con 10!`; }
            eventos.push({ minuto: minReal, tipo_evento: 'lesion', id_futbolista: lesionado.id_futbolista, descripcion: desc });
          }
        }

        // TARJETAS
        if (Math.random() < 0.04) {
          const equipoFalta = Math.random() < 0.5 ? local : visit;
          if (equipoFalta.titulares.length > 0) {
            const infractor = equipoFalta.titulares[Math.floor(Math.random() * equipoFalta.titulares.length)];
            statsPartido[infractor.id_futbolista].amarillas++;
            if (statsPartido[infractor.id_futbolista].amarillas === 2 || Math.random() < 0.1) {
              statsPartido[infractor.id_futbolista].rojas = 1;
              equipoFalta.titulares = equipoFalta.titulares.filter(j => j.id_futbolista !== infractor.id_futbolista);
              equipoFalta.rojas++;
              eventos.push({ minuto: minReal, tipo_evento: 'roja', id_futbolista: infractor.id_futbolista, descripcion: `🟥 ROJA DIRECTA a ${infractor.nombre}.` });
              if (equipoFalta.rojas >= 3) {
                partidoSuspendido = true;
                if (equipoFalta === local) { golesLocal = 0; golesVisit = 3; } else { golesLocal = 3; golesVisit = 0; }
                eventos.push({ minuto: minReal, tipo_evento: 'info', descripcion: `⚖️ FORFAIT. Suspendido por falta de jugadores. Derrota 3-0.` });
              }
            } else {
              eventos.push({ minuto: minReal, tipo_evento: 'amarilla', id_futbolista: infractor.id_futbolista, descripcion: `🟨 Amarilla para ${infractor.nombre}.` });
            }
          }
        }
      }

      // --- 3. POST-PARTIDO: Notas y Fluctuaciones ---
      for (let id in statsPartido) {
        let st = statsPartido[id];
        if (!st.jugo) continue;
        let nota = (Math.random() * 5.0) + 2.0; 
        nota += (st.goles * 2.0) + (st.asistencias * 1.5);
        if (st.rojas > 0) nota = 1.0; else if (st.amarillas > 0) nota -= 1.0;
        if (st.equipo === partido.equipo_local && golesVisit === 0 && (st.posicion === 'DF' || st.posicion === 'PT')) nota += 1.5;
        if (st.equipo === partido.equipo_visitante && golesLocal === 0 && (st.posicion === 'DF' || st.posicion === 'PT')) nota += 1.5;
        st.nota_final = Math.max(0, Math.min(10, nota)).toFixed(1);

        if (st.lesion_sufrida) await db.query(`UPDATE futbolistas SET estado_lesion = $1, partidos_lesion = $2 WHERE id_futbolista = $3`, [st.lesion_sufrida.tipo, st.lesion_sufrida.dias, st.id_futbolista]);
        if (st.rojas > 0) await db.query(`UPDATE futbolistas SET partidos_sancion = $1 WHERE id_futbolista = $2`, [Math.floor(Math.random() * 4) + 1, st.id_futbolista]);

        // Subidas y bajadas solo para no-ultras
        if (st.tipo_carta !== 'ultra') {
          let nuevaMedia = st.media;
          if (st.nota_final > 7.5 && Math.random() < ((100 - st.media) / 100)) nuevaMedia = Math.min(94, nuevaMedia + 1);
          if (st.nota_final < 4.0 && Math.random() < 0.3) nuevaMedia = Math.max(60, nuevaMedia - 1);
          let nuevoPrecio = Math.min(50000000, Math.max(1000000, Math.floor(Math.pow(1.15, nuevaMedia - 60) * 1000000)));
          await db.query(`UPDATE futbolistas SET forma_actual = $1, media = $2, precio = $3 WHERE id_futbolista = $4`, [st.nota_final, nuevaMedia, nuevoPrecio, st.id_futbolista]);
        } else {
          await db.query(`UPDATE futbolistas SET forma_actual = $1 WHERE id_futbolista = $2`, [st.nota_final, st.id_futbolista]);
        }
      }

      await db.query(`UPDATE partidos SET goles_local = $1, goles_visitante = $2, estado = 'finalizado', alineaciones = $4 WHERE id_partido = $3`, [golesLocal, golesVisit, partido.id_partido, JSON.stringify(alineacionGuardada)]);
      for (const ev of eventos) {
        await db.query(`INSERT INTO eventos_partido (id_partido, minuto, tipo_evento, id_futbolista, id_asistente, descripcion) VALUES ($1, $2, $3, $4, $5, $6)`, [partido.id_partido, ev.minuto, ev.tipo_evento, ev.id_futbolista, ev.id_asistente, ev.descripcion]);
      }

      // --- 4. PUNTOS FANTASY + MAGIA HABILIDADES ---
      const mánagers = await db.query(`SELECT DISTINCT id_user FROM users_liga WHERE id_liga = $1`, [partido.id_liga]);
      for (const man of mánagers.rows) {
        const suPlantilla = await db.query(`SELECT ful.*, f.codigo_habilidad FROM futbolista_user_liga ful JOIN futbolistas f ON ful.id_futbolista = f.id_futbolista WHERE ful.id_user = $1 AND ful.id_liga = $2 AND ful.es_titular = true`, [man.id_user, partido.id_liga]);
        let puntosTotalesManager = 0;

        const jugador12 = suPlantilla.rows.find(j => j.hueco_plantilla === 'hueco-12');
        const ultraCode = jugador12 ? jugador12.codigo_habilidad : null;
        let espejismoActivo = suPlantilla.rows.some(j => j.codigo_habilidad === 'HabEspecial_Espejismo' && j.hueco_plantilla !== 'hueco-12') && (Math.random() < 0.10);
        let bonusLider = suPlantilla.rows.filter(j => j.codigo_habilidad === 'HabEspecial_LiderEspiritual' && j.hueco_plantilla !== 'hueco-12').length;
        let primeraRojaPerdonada = false;

        for (const mio of suPlantilla.rows) {
          if (mio.hueco_plantilla === 'hueco-12') continue;
          const st = statsPartido[mio.id_futbolista];
          if (st && st.jugo) {
            const hab = mio.codigo_habilidad;
            let misPuntos = Math.round(parseFloat(st.nota_final));
            let multGoles = hab === 'HabEspecial_Francotirador' ? 10 : 5;
            
            if (st.rojas > 0) {
                if (ultraCode === 'HabUltra_Wade' && !primeraRojaPerdonada) { primeraRojaPerdonada = true; } else if (hab !== 'HabEspecial_JuegoCaballeros') { misPuntos -= 5; }
            } else if (st.amarillas > 0 && hab !== 'HabEspecial_JuegoCaballeros') { misPuntos -= 2; }

            misPuntos += (st.goles * multGoles) + (st.asistencias * 3);
            const isLocal = st.equipo === partido.equipo_local;
            const golesEquipo = isLocal ? golesLocal : golesVisit;
            const golesRival = isLocal ? golesVisit : golesLocal;
            const win = golesEquipo > golesRival;
            const loss = golesEquipo < golesRival;

            // Habilidades Especiales
            if (hab === 'HabEspecial_Egoista' && st.goles > 0 && st.goles === golesEquipo) misPuntos += 10;
            if (hab === 'HabEspecial_EfectoBolaNieve') misPuntos += golesEquipo;
            if (hab === 'HabEspecial_HeroeAgonico' && win && eventos.some(e => e.id_futbolista === mio.id_futbolista && e.minuto >= 50 && e.tipo_evento === 'gol')) misPuntos += 8;
            if (hab === 'HabEspecial_CerrojoAbsoluto' && golesRival === 0) misPuntos = Math.round(misPuntos * 1.5);
            if (hab === 'HabEspecial_SalvadorAlambre' && win && (golesEquipo - golesRival === 1)) misPuntos += 7;
            if (hab === 'HabEspecial_TodoONada') { misPuntos = win ? misPuntos * 2 : 0; }
            if (hab === 'HabEspecial_DadoDelCaos') misPuntos += (Math.random() > 0.5 ? 10 : -5);
            if (hab === 'HabEspecial_ImanFaltas') misPuntos += Math.floor(Math.random() * 5) + 1;
            if (hab === 'HabEspecial_Trotamundos' && !isLocal) misPuntos += 3;
            if (hab === 'HabEspecial_AnclaLocal' && isLocal) misPuntos += 4;
            if (hab === 'HabEspecial_OrgulloCaido' && loss && (golesRival - golesEquipo >= 3) && misPuntos < 2) misPuntos = 2;

            misPuntos += bonusLider;
            if (espejismoActivo) misPuntos *= 2;

            // Habilidades Ultra (Jugador 12)
            if (ultraCode === 'HabUltra_Trebolin' && (st.posicion === 'DF' || st.posicion === 'PT')) misPuntos = Math.round(misPuntos * 1.20);
            if (ultraCode === 'HabUltra_Wade') misPuntos = Math.round(misPuntos * 1.10);
            if (ultraCode === 'HabUltra_Cuestarriba' && (st.posicion === 'DF' || st.posicion === 'MC')) misPuntos += 3;
            if (ultraCode === 'HabUltra_Evil' && st.posicion === 'DL') {
                const golesLocalHT = eventos.filter(e => e.tipo_evento === 'gol' && e.minuto <= 30 && local.titulares.some(j=>j.id_futbolista === e.id_futbolista)).length;
                const golesVisitHT = eventos.filter(e => e.tipo_evento === 'gol' && e.minuto <= 30 && visit.titulares.some(j=>j.id_futbolista === e.id_futbolista)).length;
                if ((isLocal && golesLocalHT < golesVisitHT) || (!isLocal && golesVisitHT < golesLocalHT)) misPuntos = Math.round(misPuntos * 1.30);
            }
            if (ultraCode === 'HabUltra_Forti' && st.posicion === 'MC') misPuntos += 4;
            if (ultraCode === 'HabUltra_Modric' && st.posicion === 'MC') misPuntos = Math.round(misPuntos * 1.20);
            if (ultraCode === 'HabUltra_Chemin' && st.posicion === 'DL') misPuntos = Math.round(misPuntos * 1.15);
            if (ultraCode === 'HabUltra_BlueBird' && (st.posicion === 'DL' || st.posicion === 'MC')) misPuntos += 3;
            if (ultraCode === 'HabUltra_Falcao' && (st.posicion === 'DL' || st.posicion === 'DF')) misPuntos += 2;
            if (ultraCode === 'HabUltra_Esnaiper' && st.posicion === 'DL') misPuntos = Math.round(misPuntos * 1.35);
            if (ultraCode === 'HabUltra_Churumbel') misPuntos += 5;

            misPuntos = Math.round(misPuntos);
            await db.query(`INSERT INTO rendimiento_partido (id_partido, id_futbolista, id_user, nota_base, puntos_totales, goles, asistencias, amarillas, rojas) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [partido.id_partido, mio.id_futbolista, man.id_user, st.nota_final, misPuntos, st.goles, st.asistencias, st.amarillas, st.rojas]);
            puntosTotalesManager += misPuntos;
          }
        }
        if (puntosTotalesManager !== 0) await db.query(`UPDATE users_liga SET puntos = puntos + $1 WHERE id_user = $2 AND id_liga = $3`, [puntosTotalesManager, man.id_user, partido.id_liga]);
      }
      await db.query('COMMIT');
    }
    res.json({ message: 'Simulación completada.' });
  } catch (err) {
    await db.query('ROLLBACK');
    console.error("Error Simulación:", err);
    res.status(500).json({ error: 'Fallo brutal en el motor' });
  }
});


// 2. Obtener la CLASIFICACIÓN GENERAL de la Liga
router.get('/:id_liga/clasificacion', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  try {
    // Unimos los usuarios con sus puntos en users_liga para sacar el ranking oficial
    const query = `
      SELECT 
        u.username AS equipo, 
        ul.puntos AS puntos_totales,
        ul.dinero AS presupuesto
      FROM users_liga ul
      JOIN users u ON ul.id_user = u.id
      WHERE ul.id_liga = $1
      ORDER BY ul.puntos DESC, ul.dinero DESC;
    `;
    const clasificacion = await db.query(query, [id_liga]);
    res.json(clasificacion.rows);
  } catch(err) {
    console.error(err);
    res.status(500).json({message: 'Error cargando clasificación general'});
  }
});

// A. Obtener lista de todos los mánagers de la liga (Para el desplegable)
router.get('/:id_liga/managers', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  try {
    const query = `
      SELECT u.id, u.username 
      FROM users_liga ul
      JOIN users u ON ul.id_user = u.id
      WHERE ul.id_liga = $1
    `;
    const result = await db.query(query, [id_liga]);
    res.json(result.rows);
  } catch(err) {
    res.status(500).json({message: 'Error cargando mánagers'});
  }
});

// B. Obtener los puntos de un Mánager concreto en una Jornada concreta
router.get('/:id_liga/puntos-jornada', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const { id_manager, jornada } = req.query;

  try {
    const query = `
      SELECT 
        f.nombre, 
        f.posicion, 
        f.precio as valor,
        rp.puntos_totales as puntos,
        rp.goles,
        rp.asistencias
      FROM rendimiento_partido rp
      JOIN partidos p ON rp.id_partido = p.id_partido
      JOIN futbolistas f ON rp.id_futbolista = f.id_futbolista
      WHERE p.id_liga = $1          -- <--- Cambiado de rp.id_liga a p.id_liga
        AND rp.id_user = $2 
        AND p.jornada = $3
      ORDER BY rp.puntos_totales DESC;
    `;
    
    // Asegúrate de pasar los parámetros como números para evitar conflictos de tipos
    const result = await db.query(query, [
      parseInt(id_liga), 
      parseInt(id_manager), 
      parseInt(jornada)
    ]);
    
    res.json(result.rows);
  } catch(err) {
    console.error("Error en puntos-jornada:", err);
    res.status(500).json({message: 'Error cargando puntos'});
  }
});


// Obtener la CLASIFICACIÓN REAL DE LOS CLUBES (Athletic Hullera, etc.)
router.get('/:id_liga/clasificacion-clubes', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  try {
    const query = `
      WITH Resultados AS (
        SELECT 
          equipo_local AS equipo,
          goles_local AS gf,
          goles_visitante AS gc,
          CASE WHEN goles_local > goles_visitante THEN 1 ELSE 0 END AS pg,
          CASE WHEN goles_local = goles_visitante THEN 1 ELSE 0 END AS pe,
          CASE WHEN goles_local < goles_visitante THEN 1 ELSE 0 END AS pp,
          CASE WHEN goles_local > goles_visitante THEN 3 WHEN goles_local = goles_visitante THEN 1 ELSE 0 END AS pts
        FROM partidos WHERE id_liga = $1 AND estado = 'finalizado'
        UNION ALL
        SELECT 
          equipo_visitante AS equipo,
          goles_visitante AS gf,
          goles_local AS gc,
          CASE WHEN goles_visitante > goles_local THEN 1 ELSE 0 END AS pg,
          CASE WHEN goles_visitante = goles_local THEN 1 ELSE 0 END AS pe,
          CASE WHEN goles_visitante < goles_local THEN 1 ELSE 0 END AS pp,
          CASE WHEN goles_visitante > goles_local THEN 3 WHEN goles_visitante = goles_local THEN 1 ELSE 0 END AS pts
        FROM partidos WHERE id_liga = $1 AND estado = 'finalizado'
      )
      SELECT 
        equipo,
        COUNT(*) AS pj,
        SUM(pg) AS pg,
        SUM(pe) AS pe,
        SUM(pp) AS pp,
        SUM(gf) AS gf,
        SUM(gc) AS gc,
        (SUM(gf) - SUM(gc)) AS dif,
        SUM(pts) AS puntos_totales
      FROM Resultados
      GROUP BY equipo
      ORDER BY puntos_totales DESC, dif DESC, gf DESC;
    `;
    const clasificacion = await db.query(query, [id_liga]);
    res.json(clasificacion.rows);
  } catch(err) {
    console.error(err);
    res.status(500).json({message: 'Error calculando la clasificación de los clubes'});
  }
});

// Export para Vercel
module.exports = app;