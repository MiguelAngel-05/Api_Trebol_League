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

// -- Funciones Importantes --
// Asignación de plantillas iniciales
async function asignarPlantillaInicialUsuario(idUser, idLiga) {
  const shuffleArray = (array) => {
    const copia = [...array];

    for (let i = copia.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [copia[i], copia[j]] = [copia[j], copia[i]];
    }

    return copia;
  };

  let posiciones = ['PT', 'DF', 'DF', 'DF', 'DF', 'MC', 'MC', 'MC', 'DL', 'DL', 'DL'];
  posiciones = shuffleArray(posiciones);

  const buckets = [
    { mMin: 60, mMax: 65, cant: 8 },
    { mMin: 66, mMax: 70, cant: 2 },
    { mMin: 75, mMax: 80, cant: 1 }
  ];

  let jugadoresAsignados = 0;

  for (const bucket of buckets) {
    for (let i = 0; i < bucket.cant; i++) {
      const posActual = posiciones.shift();

      const player = await db.query(`
        SELECT id_futbolista 
        FROM futbolistas 
        WHERE media BETWEEN $1 AND $2 
          AND TRIM(UPPER(posicion)) = $3 
          AND tipo_carta = 'normal'
          AND equipo != 'Real Trébol FC'
          AND id_futbolista NOT IN (
            SELECT id_futbolista 
            FROM futbolista_user_liga 
            WHERE id_liga = $4
          )
          AND id_futbolista NOT IN (
            SELECT id_futbolista
            FROM mercado_liga
            WHERE id_liga = $4
          )
        ORDER BY RANDOM() 
        LIMIT 1
      `, [bucket.mMin, bucket.mMax, posActual, idLiga]);

      if (player.rows.length > 0) {
        await db.query(`
          INSERT INTO futbolista_user_liga 
          (id_user, id_liga, id_futbolista, es_titular, hueco_plantilla, en_venta, precio_venta)
          VALUES ($1, $2, $3, false, NULL, false, 0)
        `, [idUser, idLiga, player.rows[0].id_futbolista]);

        jugadoresAsignados++;
      }
    }
  }

  return jugadoresAsignados;
}

// Bloquear alineaciones para cada jornada
async function bloquearAlineacionesJornada(idLiga, jornada) {
  const yaBloqueada = await db.query(`
    SELECT 1
    FROM alineaciones_jornada
    WHERE id_liga = $1
      AND jornada = $2
    LIMIT 1
  `, [idLiga, jornada]);

  if (yaBloqueada.rows.length > 0) {
    return { bloqueada: false, motivo: 'La jornada ya estaba bloqueada' };
  }

  const usuariosRes = await db.query(`
    SELECT 
      ul.id_user,
      COALESCE(ul.formacion, '4-3-3') AS formacion
    FROM users_liga ul
    WHERE ul.id_liga = $1
  `, [idLiga]);

  const huecosObligatorios = [
    'hueco-1',
    'hueco-2',
    'hueco-3',
    'hueco-4',
    'hueco-5',
    'hueco-6',
    'hueco-7',
    'hueco-8',
    'hueco-9',
    'hueco-10',
    'hueco-11'
  ];

  let totalUsuarios = 0;
  let totalHuecosVacios = 0;
  let totalJugadoresBloqueados = 0;

  for (const usuario of usuariosRes.rows) {
    totalUsuarios++;

    const titularesRes = await db.query(`
      SELECT 
        ful.id_futbolista,
        ful.hueco_plantilla,
        f.nombre,
        f.posicion,
        f.media,
        f.tipo_carta,
        f.codigo_habilidad
      FROM futbolista_user_liga ful
      JOIN futbolistas f ON f.id_futbolista = ful.id_futbolista
      WHERE ful.id_liga = $1
        AND ful.id_user = $2
        AND ful.es_titular = true
        AND ful.hueco_plantilla IS NOT NULL
    `, [idLiga, usuario.id_user]);

    const porHueco = new Map();

    for (const jugador of titularesRes.rows) {
      porHueco.set(jugador.hueco_plantilla, jugador);
    }

    for (const hueco of huecosObligatorios) {
      const jugador = porHueco.get(hueco);

      if (jugador) {
        await db.query(`
          INSERT INTO alineaciones_jornada (
            id_liga,
            jornada,
            id_user,
            id_futbolista,
            hueco_plantilla,
            es_hueco_vacio,
            tipo_carta_snapshot,
            nombre_snapshot,
            posicion_snapshot,
            media_snapshot,
            codigo_habilidad_snapshot
          )
          VALUES ($1,$2,$3,$4,$5,false,$6,$7,$8,$9,$10)
          ON CONFLICT (id_liga, jornada, id_user, hueco_plantilla) DO NOTHING
        `, [
          idLiga,
          jornada,
          usuario.id_user,
          jugador.id_futbolista,
          hueco,
          jugador.tipo_carta,
          jugador.nombre,
          jugador.posicion,
          jugador.media,
          jugador.codigo_habilidad
        ]);

        totalJugadoresBloqueados++;
      } else {
        await db.query(`
          INSERT INTO alineaciones_jornada (
            id_liga,
            jornada,
            id_user,
            id_futbolista,
            hueco_plantilla,
            es_hueco_vacio
          )
          VALUES ($1,$2,$3,NULL,$4,true)
          ON CONFLICT (id_liga, jornada, id_user, hueco_plantilla) DO NOTHING
        `, [
          idLiga,
          jornada,
          usuario.id_user,
          hueco
        ]);

        totalHuecosVacios++;
      }
    }

    const jugador12 = porHueco.get('hueco-12');

    if (jugador12) {
      await db.query(`
        INSERT INTO alineaciones_jornada (
          id_liga,
          jornada,
          id_user,
          id_futbolista,
          hueco_plantilla,
          es_hueco_vacio,
          tipo_carta_snapshot,
          nombre_snapshot,
          posicion_snapshot,
          media_snapshot,
          codigo_habilidad_snapshot
        )
        VALUES ($1,$2,$3,$4,'hueco-12',false,$5,$6,$7,$8,$9)
        ON CONFLICT (id_liga, jornada, id_user, hueco_plantilla) DO NOTHING
      `, [
        idLiga,
        jornada,
        usuario.id_user,
        jugador12.id_futbolista,
        jugador12.tipo_carta,
        jugador12.nombre,
        jugador12.posicion,
        jugador12.media,
        jugador12.codigo_habilidad
      ]);
    }
  }

  return {
    bloqueada: true,
    usuarios: totalUsuarios,
    jugadores: totalJugadoresBloqueados,
    huecos_vacios: totalHuecosVacios
  };
}
async function debeBloquearJornada(idLiga, jornada) {
  const yaBloqueada = await db.query(`
    SELECT 1
    FROM alineaciones_jornada
    WHERE id_liga = $1
      AND jornada = $2
    LIMIT 1
  `, [idLiga, jornada]);

  if (yaBloqueada.rows.length > 0) {
    return false;
  }

  const primerPartidoRes = await db.query(`
    SELECT fecha_partido
    FROM partidos
    WHERE id_liga = $1
      AND jornada = $2
    ORDER BY fecha_partido ASC
    LIMIT 1
  `, [idLiga, jornada]);

  if (primerPartidoRes.rows.length === 0) {
    return false;
  }

  const primerPartido = new Date(primerPartidoRes.rows[0].fecha_partido).getTime();
  const ahora = Date.now();

  return ahora >= primerPartido;
}

// Aplicar penalización de -3 por jornada por huecos vacios
async function aplicarPenalizacionesHuecosVaciosJornada(idLiga, jornada, idPartidoReferencia) {
  const usuariosRes = await db.query(`
    SELECT DISTINCT id_user
    FROM alineaciones_jornada
    WHERE id_liga = $1
      AND jornada = $2
  `, [idLiga, jornada]);

  for (const usuario of usuariosRes.rows) {
    const yaPenalizado = await db.query(`
      SELECT 1
      FROM rendimiento_partido rp
      JOIN partidos p ON p.id_partido = rp.id_partido
      WHERE p.id_liga = $1
        AND p.jornada = $2
        AND rp.id_user = $3
        AND rp.tipo_registro = 'hueco_vacio'
      LIMIT 1
    `, [idLiga, jornada, usuario.id_user]);

    if (yaPenalizado.rows.length > 0) {
      continue;
    }

    const huecosRes = await db.query(`
      SELECT hueco_plantilla
      FROM alineaciones_jornada
      WHERE id_liga = $1
        AND jornada = $2
        AND id_user = $3
        AND es_hueco_vacio = true
        AND hueco_plantilla != 'hueco-12'
    `, [idLiga, jornada, usuario.id_user]);

    for (const hueco of huecosRes.rows) {
      await db.query(`
        INSERT INTO rendimiento_partido
        (
          id_partido,
          id_futbolista,
          id_user,
          nota_base,
          puntos_totales,
          goles,
          asistencias,
          amarillas,
          rojas,
          tipo_registro,
          hueco_plantilla
        )
        VALUES ($1, NULL, $2, NULL, -3, 0, 0, 0, 0, 'hueco_vacio', $3)
      `, [
        idPartidoReferencia,
        usuario.id_user,
        hueco.hueco_plantilla
      ]);

      await db.query(`
        UPDATE users_liga
        SET puntos = puntos - 3
        WHERE id_user = $1
          AND id_liga = $2
      `, [usuario.id_user, idLiga]);
    }
  }
}


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
      [idUser, idLiga, 'owner', 0, 0]
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
    await db.query('BEGIN');

    const ligaResult = await db.query(`
      SELECT *
      FROM ligas
      WHERE id_liga = $1
      FOR UPDATE
    `, [id_liga]);

    if (!ligaResult.rows[0]) {
      throw new Error('Liga no encontrada');
    }

    const liga = ligaResult.rows[0];

    if (liga.clave !== clave) {
      await db.query('ROLLBACK');
      return res.status(403).json({ message: 'Clave incorrecta' });
    }

    if (Number(liga.numero_jugadores) >= Number(liga.max_jugadores)) {
      await db.query('ROLLBACK');
      return res.status(403).json({ message: 'Liga llena' });
    }

    const yaExiste = await db.query(`
      SELECT 1
      FROM users_liga
      WHERE id_user = $1
        AND id_liga = $2
    `, [idUser, id_liga]);

    if (yaExiste.rows.length > 0) {
      await db.query('ROLLBACK');
      return res.status(400).json({ message: 'Ya estás en esta liga' });
    }

    const temporadaActiva = liga.temporada_estado === 'activa' || liga.temporada_estado === 'finalizada';
    const dineroEntrada = temporadaActiva
      ? Number(liga.dinero_inicial || 100000000)
      : 100000000;

    await db.query(`
      INSERT INTO users_liga 
      (id_user, id_liga, rol, dinero, puntos)
      VALUES ($1, $2, 'user', $3, 0)
    `, [idUser, id_liga, dineroEntrada]);

    await db.query(`
      UPDATE ligas 
      SET numero_jugadores = numero_jugadores + 1 
      WHERE id_liga = $1
    `, [id_liga]);

    let jugadoresAsignados = 0;

    if (temporadaActiva && liga.dar_plantilla_inicial === true) {
      jugadoresAsignados = await asignarPlantillaInicialUsuario(idUser, id_liga);
    }

    await db.query('COMMIT');

    res.json({
      message: temporadaActiva
        ? `Te has unido a la liga. Has recibido ${dineroEntrada} Tc${liga.dar_plantilla_inicial ? ` y ${jugadoresAsignados} jugadores.` : '.'}`
        : 'Te has unido a la liga',
      id_liga,
      dinero: dineroEntrada,
      jugadores_asignados: jugadoresAsignados
    });

  } catch (err) {
    await db.query('ROLLBACK');

    console.error('Error al unirse a la liga:', err);

    if (err.code === '23505') {
      return res.status(400).json({ message: 'Ya estás en esta liga' });
    }

    res.status(500).json({ message: err.message || 'Error al unirse a la liga' });
  }
});

// Eliminar una liga 
router.delete('/:id_liga', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
  const { id_liga } = req.params;
  try {
    await db.query('BEGIN');
    
    await db.query('DELETE FROM historial_transferencias WHERE id_liga=$1', [id_liga]);
    await db.query('DELETE FROM mercado_liga WHERE id_liga=$1', [id_liga]);
    await db.query('DELETE FROM pujas WHERE id_liga=$1', [id_liga]);
    await db.query('DELETE FROM mensajes_privados WHERE id_liga=$1', [id_liga]);
    await db.query('DELETE FROM ofertas_privadas WHERE id_liga=$1', [id_liga]);
    await db.query('DELETE FROM chat_general WHERE id_liga=$1', [id_liga]);
    await db.query('DELETE FROM rendimiento_partido WHERE id_partido IN (SELECT id_partido FROM partidos WHERE id_liga=$1)', [id_liga]);
    await db.query('DELETE FROM eventos_partido WHERE id_partido IN (SELECT id_partido FROM partidos WHERE id_liga=$1)', [id_liga]);
    await db.query('DELETE FROM partidos WHERE id_liga=$1', [id_liga]);
    await db.query('DELETE FROM futbolista_user_liga WHERE id_liga=$1', [id_liga]);
    await db.query('DELETE FROM users_liga WHERE id_liga=$1', [id_liga]);
    await db.query('DELETE FROM ligas WHERE id_liga=$1', [id_liga]);
    
    await db.query('COMMIT');
    res.json({ message: 'Liga eliminada por completo' });
  } catch (err) {
    await db.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: 'Error eliminando liga' });
  }
});

// Ver ligas de un usuario
app.get('/api/mis-ligas', verifyToken, async (req, res) => {
  try {
    const result = await db.query(`
      WITH jornadas_finalizadas AS (
        SELECT id_liga, jornada
        FROM partidos
        GROUP BY id_liga, jornada
        HAVING BOOL_AND(
          estado = 'finalizado'
          AND fecha_partido + interval '70 minutes' <= NOW()
        )
      ),
      puntos_visibles AS (
        SELECT 
          p.id_liga,
          rp.id_user,
          SUM(rp.puntos_totales) AS puntos
        FROM rendimiento_partido rp
        JOIN partidos p ON p.id_partido = rp.id_partido
        JOIN jornadas_finalizadas jf
          ON jf.id_liga = p.id_liga
          AND jf.jornada = p.jornada
        GROUP BY p.id_liga, rp.id_user
      )
      SELECT 
        l.id_liga,
        l.nombre,
        l.numero_jugadores,
        l.max_jugadores,
        ul.dinero,
        ul.rol,

        COALESCE(pv.puntos, 0) AS puntos

      FROM users_liga ul
      JOIN ligas l ON l.id_liga = ul.id_liga

      LEFT JOIN puntos_visibles pv
        ON pv.id_liga = ul.id_liga
        AND pv.id_user = ul.id_user

      WHERE ul.id_user = $1

      ORDER BY l.id_liga DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error obteniendo ligas' });
  }
});

// Salir de una liga
router.delete('/:id_liga/salir', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const idUser = req.user.id;

  try {
    await db.query('BEGIN');

    const userLigaRes = await db.query(`
      SELECT rol
      FROM users_liga
      WHERE id_liga = $1
        AND id_user = $2
      FOR UPDATE
    `, [id_liga, idUser]);

    if (userLigaRes.rows.length === 0) {
      await db.query('ROLLBACK');
      return res.status(404).json({ message: 'No perteneces a esta liga' });
    }

    const rol = userLigaRes.rows[0].rol;

    if (rol === 'owner') {
      await db.query('ROLLBACK');
      return res.status(400).json({
        message: 'El creador no puede salir de la liga. Debe eliminar la liga o transferir la propiedad.'
      });
    }

    // Eliminar pujas del usuario en esa liga
    await db.query(`
      DELETE FROM pujas
      WHERE id_liga = $1
        AND id_user = $2
    `, [id_liga, idUser]);

    // Eliminar ofertas privadas donde participa
    await db.query(`
      DELETE FROM ofertas_privadas
      WHERE id_liga = $1
        AND (id_comprador = $2 OR id_vendedor = $2)
    `, [id_liga, idUser]);

    // Eliminar mensajes privados enviados o recibidos
    await db.query(`
      DELETE FROM mensajes_privados
      WHERE id_liga = $1
        AND (id_remitente = $2 OR id_destinatario = $2)
    `, [id_liga, idUser]);

    // Eliminar mensajes del chat general del usuario
    await db.query(`
      DELETE FROM chat_general
      WHERE id_liga = $1
        AND id_user = $2
    `, [id_liga, idUser]);

    // Eliminar jugadores del usuario en esa liga
    await db.query(`
      DELETE FROM futbolista_user_liga
      WHERE id_liga = $1
        AND id_user = $2
    `, [id_liga, idUser]);

    // Eliminar alineaciones bloqueadas del usuario en esa liga
    await db.query(`
      DELETE FROM alineaciones_jornada
      WHERE id_liga = $1
        AND id_user = $2
    `, [id_liga, idUser]);

    // Eliminar rendimiento del usuario en partidos de esa liga
    await db.query(`
      DELETE FROM rendimiento_partido
      WHERE id_user = $1
        AND id_partido IN (
          SELECT id_partido
          FROM partidos
          WHERE id_liga = $2
        )
    `, [idUser, id_liga]);

    // Eliminar historial de transferencias donde participa el usuario
    await db.query(`
      DELETE FROM historial_transferencias
      WHERE id_liga = $1
        AND (id_comprador = $2 OR id_vendedor = $2)
    `, [id_liga, idUser]);

    // Sacar al usuario de la liga
    await db.query(`
      DELETE FROM users_liga
      WHERE id_liga = $1
        AND id_user = $2
    `, [id_liga, idUser]);

    // Actualizar contador de jugadores
    await db.query(`
      UPDATE ligas
      SET numero_jugadores = GREATEST(0, numero_jugadores - 1)
      WHERE id_liga = $1
    `, [id_liga]);

    await db.query('COMMIT');

    res.json({ message: 'Has salido de la liga correctamente' });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error('Error saliendo de la liga:', err);
    res.status(500).json({ message: 'Error al salir de la liga' });
  }
});


// --- RUTAS DE Mi plantilla y Plantilla Rival ---
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

    // Actualizar la formación preferida del usuario en esta liga
    if (formacion) {
      await db.query(
        'UPDATE users_liga SET formacion = $1 WHERE id_user = $2 AND id_liga = $3',
        [formacion, idUser, id_liga]
      );
    }

    // Mandar a TODOS los jugadores al banquillo y limpiar su hueco
    await db.query(
      'UPDATE futbolista_user_liga SET es_titular = false, hueco_plantilla = NULL WHERE id_user = $1 AND id_liga = $2',
      [idUser, id_liga]
    );

    // Ascender a titulares a los que estén en el césped en su hueco específico
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

// Ver la plantilla de un rival
router.get('/:id_liga/jugadores-rival/:id_user', verifyToken, async (req, res) => {
  const { id_liga, id_user } = req.params;
  try {
    // Buscamos primero quién es el rival para sacar su nombre y avatar
    const rivalRes = await db.query('SELECT username, avatar FROM users WHERE id = $1', [id_user]);
    
    if (rivalRes.rows.length === 0) {
      return res.status(404).json({ message: 'Rival no encontrado' });
    }

    // Buscamos a sus jugadores
    const jugRes = await db.query(`
      SELECT f.*, ful.es_titular, ful.hueco_plantilla, ful.en_venta, ful.precio_venta
      FROM futbolista_user_liga ful 
      JOIN futbolistas f ON f.id_futbolista = ful.id_futbolista
      WHERE ful.id_liga = $1 AND ful.id_user = $2
    `, [id_liga, id_user]);

    // Empaquetamos todo exactamente como tu Frontend (plantilla-rival.ts) lo espera
    res.json({
      rival: rivalRes.rows[0],
      jugadores: jugRes.rows
    });
    
  } catch (err) {
    res.status(500).json({ message: 'Error obteniendo jugadores del rival' });
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


// --- RUTAS DE ADMINISTRACION DE LA LIGA Y USUARIO ---
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

// Obtener el Roster, Lore, Noticias y ÚLTIMO PARTIDO de un equipo
router.get('/:id_liga/club/:nombre_club', verifyToken, async (req, res) => {
  const { id_liga, nombre_club } = req.params;
  try {
    // 1. Plantilla Normal
    const jugRes = await db.query(`
      SELECT f.id_futbolista, f.nombre, f.posicion, f.media, f.tipo_carta, f.imagen,
             f.partidos_lesion, f.partidos_sancion, f.estado_lesion, f.forma_actual,
             COALESCE(goles.total, 0) as goles, COALESCE(asistencias.total, 0) as asistencias,
             COALESCE(amarillas.total, 0) as amarillas, COALESCE(rojas.total, 0) as rojas
      FROM futbolistas f
      LEFT JOIN (SELECT id_futbolista, COUNT(*) as total FROM eventos_partido ep JOIN partidos p ON p.id_partido = ep.id_partido WHERE p.id_liga = $1 AND tipo_evento = 'gol' GROUP BY id_futbolista) goles ON f.id_futbolista = goles.id_futbolista
      LEFT JOIN (SELECT id_asistente as id_futbolista, COUNT(*) as total FROM eventos_partido ep JOIN partidos p ON p.id_partido = ep.id_partido WHERE p.id_liga = $1 AND tipo_evento = 'gol' AND id_asistente IS NOT NULL GROUP BY id_asistente) asistencias ON f.id_futbolista = asistencias.id_futbolista
      LEFT JOIN (SELECT id_futbolista, COUNT(*) as total FROM eventos_partido ep JOIN partidos p ON p.id_partido = ep.id_partido WHERE p.id_liga = $1 AND tipo_evento = 'amarilla' GROUP BY id_futbolista) amarillas ON f.id_futbolista = amarillas.id_futbolista
      LEFT JOIN (SELECT id_futbolista, COUNT(*) as total FROM eventos_partido ep JOIN partidos p ON p.id_partido = ep.id_partido WHERE p.id_liga = $1 AND tipo_evento = 'roja' GROUP BY id_futbolista) rojas ON f.id_futbolista = rojas.id_futbolista
      WHERE f.equipo = $2 AND f.tipo_carta = 'normal'
      ORDER BY f.media DESC
    `, [id_liga, nombre_club]);

    // 2. Último Partido
    const ultimoPartidoRes = await db.query(`
      SELECT * 
      FROM partidos 
      WHERE id_liga = $1 
        AND (equipo_local = $2 OR equipo_visitante = $2) 
        AND estado = 'finalizado'
        AND fecha_partido + interval '70 minutes' <= NOW()
      ORDER BY fecha_partido DESC 
      LIMIT 1
    `, [id_liga, nombre_club]);

    let ultimoPartido = null;
    if (ultimoPartidoRes.rows.length > 0) {
      ultimoPartido = ultimoPartidoRes.rows[0];
      if (typeof ultimoPartido.alineaciones === 'string') {
        try { ultimoPartido.alineaciones = JSON.parse(ultimoPartido.alineaciones); } catch (e) { ultimoPartido.alineaciones = null; }
      }
      const eventosRes = await db.query('SELECT * FROM eventos_partido WHERE id_partido = $1', [ultimoPartido.id_partido]);
      ultimoPartido.eventos = eventosRes.rows;
    }

    // 3. Noticias (Últimas lesiones y sanciones de ESTE equipo en la liga)
    const noticiasRes = await db.query(`
      SELECT e.minuto, e.tipo_evento, e.descripcion, p.jornada 
      FROM eventos_partido e 
      JOIN partidos p ON e.id_partido = p.id_partido 
      JOIN futbolistas f ON e.id_futbolista = f.id_futbolista 
      WHERE p.id_liga = $1 
        AND f.equipo = $2 
        AND e.tipo_evento IN ('lesion', 'roja', 'amarilla')
        AND p.estado = 'finalizado'
        AND p.fecha_partido + interval '70 minutes' <= NOW()
      ORDER BY p.fecha_partido DESC, e.minuto DESC 
      LIMIT 15
    `, [id_liga, nombre_club]);

    const lores = {
      'Real Trébol FC': 'Los Dioses fundadores de la liga. Invencibles en su estadio.',
      'Motor Club Chacón': 'Velocidad, gasolina y rock n roll. Su ataque es temible.',
      'Athletic Hullera': 'Mineros duros de roer. Su defensa es un muro de piedra.',
      'Deportivo Relámpago': 'El equipo del pueblo, conocido por sus contraataques fugaces.',
      'Real Pinar FC': 'Los reyes del bosque. Fútbol elegante y de toque.',
      'Neón City FC': 'Fútbol futurista bajo las luces de la ciudad.',
      'Pixel United': 'Construyen el juego pase a pase, bloque a bloque.',
      'CF Átomo': 'Pequeños pero explosivos. Energía inagotable.',
      'Club Náutico Brisamar': 'Juegan al ritmo de las olas. Un fútbol fluido y refrescante.',
      'Racing Vaguadas': 'Especialistas en barrizales. Nunca dan un balón por perdido.',
      'UD Recreo': 'Siempre ofensivos, siempre buscando el espectáculo.',
      'Alianza Metropolitana': 'El orden táctico hecho equipo.',
      'Gourmet FC': 'Fútbol exquisito para paladares finos.',
      'Cosmos United': 'Estrellas brillantes con un fútbol espacial.',
      'Dragones de Oriente': 'Su fuego arrasa con cualquier defensa.',
      'CD Refugio': 'Su estadio es un fortín inexpugnable.',
      'Unión Fortaleza': 'Disciplina militar. Una defensa de hierro.',
      'CD Frontera': 'Expertos en ganar partidos en el último suspiro.',
      'Sporting Lechuza': 'Sus mejores resultados llegan bajo los focos nocturnos.',
      'Titanes CF': 'Gigantes del área. Dominan el juego aéreo.',
      'Pangea FC': 'Un equipo que une todos los estilos de fútbol.'
    };

    res.json({
      equipo: nombre_club,
      lore: lores[nombre_club] || 'Un club histórico de Isla Trébol.',
      plantilla: jugRes.rows,
      ultimo_partido: ultimoPartido,
      noticias: noticiasRes.rows
    });
  } catch(err) {
    res.status(500).json({message: 'Error cargando el club'});
  }
});

// Configurar perfil de usuario
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

// Consulta de alineación bloqueada
router.get('/:id_liga/alineacion-jornada/:jornada/:id_user', verifyToken, async (req, res) => {
  const { id_liga, jornada, id_user } = req.params;

  try {
    const result = await db.query(`
      SELECT 
        id_liga,
        jornada,
        id_user,
        id_futbolista,
        hueco_plantilla,
        es_hueco_vacio,
        tipo_carta_snapshot,
        nombre_snapshot,
        posicion_snapshot,
        media_snapshot,
        codigo_habilidad_snapshot,
        fecha_bloqueo
      FROM alineaciones_jornada
      WHERE id_liga = $1
        AND jornada = $2
        AND id_user = $3
      ORDER BY 
        CASE 
          WHEN hueco_plantilla = 'hueco-12' THEN 12
          ELSE CAST(REPLACE(hueco_plantilla, 'hueco-', '') AS integer)
        END ASC
    `, [id_liga, jornada, id_user]);

    res.json(result.rows);
  } catch (err) {
    console.error('Error obteniendo alineación bloqueada:', err);
    res.status(500).json({ message: 'Error obteniendo alineación bloqueada' });
  }
});


//CALENDARIO
// Generar el calendario de la liga y configurar la temporada
router.post('/:id_liga/generar-calendario', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
  const { id_liga } = req.params;
  const { dineroInicial, darPlantilla } = req.body; 

  try {
    await db.query('BEGIN'); 

    // Comprobar si ya hay partidos generados
    const checkPartidos = await db.query('SELECT id_partido FROM partidos WHERE id_liga = $1 LIMIT 1', [id_liga]);
    if (checkPartidos.rows.length > 0) {
      throw new Error('La liga ya tiene un calendario generado.');
    }

    // Asignar el presupuesto inicial a todos los mánagers
    if (dineroInicial !== undefined) {
      await db.query('UPDATE users_liga SET dinero = $1 WHERE id_liga = $2', [dineroInicial, id_liga]);
    }

    //Guardar la configuración de la liga
    await db.query(`
      UPDATE ligas
      SET 
        temporada_estado = 'activa',
        dinero_inicial = $1,
        dar_plantilla_inicial = $2,
        fecha_inicio_temporada = COALESCE(fecha_inicio_temporada, NOW()),
        fecha_fin_temporada = NULL,
        reset_automatico_en = NULL
      WHERE id_liga = $3
    `, [
      dineroInicial !== undefined ? dineroInicial : 100000000,
      !!darPlantilla,
      id_liga
    ]);

    // Reparto de plantillas
    if (darPlantilla) {
      await db.query('DELETE FROM futbolista_user_liga WHERE id_liga = $1', [id_liga]);

      const usersRes = await db.query('SELECT id_user FROM users_liga WHERE id_liga = $1', [id_liga]);
      
      const shuffleArray = (array) => {
        for (let i = array.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [array[i], array[j]] = [array[j], array[i]];
        }
        return array;
      };

      for (const u of usersRes.rows) {
        await asignarPlantillaInicialUsuario(u.id_user, id_liga);
      }
    }

    // Preparar calendario
    const teamsRes = await db.query("SELECT DISTINCT equipo FROM futbolistas WHERE equipo != 'Real Trébol FC'");
    let equipos = teamsRes.rows.map(row => row.equipo);

    if (equipos.length < 2) {
      throw new Error('No hay suficientes equipos en la base de datos para jugar.');
    }

    for (let i = equipos.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [equipos[i], equipos[j]] = [equipos[j], equipos[i]];
    }

    if (equipos.length % 2 !== 0) equipos.push('DESCANSA'); 

    const totalEquipos = equipos.length;
    const totalJornadasIda = totalEquipos - 1;
    const partidosPorJornada = totalEquipos / 2;
    let calendario = [];

    // Asignación de partidos
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

    // Reparto de días (Fechas, Horas y Descansos)
    let currentDate = new Date();
    currentDate.setDate(currentDate.getDate() + 7); 
    currentDate.setHours(0, 0, 0, 0);

    const timeSlots = [ { h: 10, m: 0 }, { h: 13, m: 0 }, { h: 17, m: 0 }, { h: 20, m: 0 } ];

    function shuffleSlots(array) {
      for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
      }
      return array;
    }

    const totalJornadas = totalJornadasIda * 2;

    for (let jornada = 1; jornada <= totalJornadas; jornada++) {
      let partidosJornada = calendario.filter(p => p.jornada === jornada && p.local !== 'DESCANSA' && p.visitante !== 'DESCANSA');
      
      const distribucion = [3, 3, 4]; 
      let partidoIndex = 0;

      for (let dayOffset = 0; dayOffset < 3; dayOffset++) {
        const partidosHoy = distribucion[dayOffset];
        const slotsHoy = shuffleSlots([...timeSlots]).slice(0, partidosHoy);
        
        for (let i = 0; i < partidosHoy; i++) {
          if (partidoIndex < partidosJornada.length) {
            const partido = partidosJornada[partidoIndex];
            
            const fechaPartido = new Date(currentDate);
            fechaPartido.setDate(fechaPartido.getDate() + dayOffset);
            
            const slotAsignado = slotsHoy[i % slotsHoy.length];
            fechaPartido.setHours(slotAsignado.h, slotAsignado.m, 0, 0); 

            await db.query(`
              INSERT INTO partidos (id_liga, jornada, equipo_local, equipo_visitante, fecha_partido, estado)
              VALUES ($1, $2, $3, $4, $5, 'pendiente')
            `, [id_liga, partido.jornada, partido.local, partido.visitante, fechaPartido]);

            partidoIndex++;
          }
        }
      }
      currentDate.setDate(currentDate.getDate() + 5); 
    }

    // Mercado inicial
    await db.query('DELETE FROM mercado_liga WHERE id_liga = $1', [id_liga]);
    await db.query('DELETE FROM historial_transferencias WHERE id_liga = $1', [id_liga]);

    const mercadoInicial = await db.query(`
      WITH Disponibles AS (
        SELECT id_futbolista, TRIM(UPPER(posicion)) as pos_limpia,
               ROW_NUMBER() OVER(PARTITION BY TRIM(UPPER(posicion)) ORDER BY RANDOM()) as rn,
               RANDOM() as rnd
        FROM futbolistas 
        WHERE equipo != 'Real Trébol FC' AND tipo_carta = 'normal' 
          AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $1)
      )
      SELECT id_futbolista FROM Disponibles ORDER BY CASE WHEN rn <= 4 THEN 0 ELSE 1 END, rnd LIMIT 20
    `, [id_liga]);

    for (const j of mercadoInicial.rows) {
      await db.query(`
        INSERT INTO mercado_liga (id_liga, id_futbolista, fecha_generacion) 
        VALUES ($1, $2, NOW()) 
        ON CONFLICT DO NOTHING
      `, [id_liga, j.id_futbolista]);
    }

    //Redondear todos los valores de mercado
    await db.query(`
        UPDATE futbolistas 
        SET precio = ROUND(precio / 100000.0) * 100000
    `);

    await db.query('COMMIT');
    res.json({ message: '¡Liga generada! Dinero y plantillas repartidas con éxito. 📅⚽' });
  } catch (err) {
    await db.query('ROLLBACK');
    console.error("Error generando calendario:", err);
    res.status(400).json({ message: err.message || 'Error al configurar y generar la liga' });
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

// Obtener el Ranking de Mánagers de UNA jornada específica
router.get('/:id_liga/ranking-jornada/:jornada', verifyToken, async (req, res) => {
  const { id_liga, jornada } = req.params;
  try {
    const query = `
      SELECT 
        u.id,
        u.username,
        u.avatar,
        COALESCE(SUM(
          CASE 
            WHEN p.id_partido IS NOT NULL THEN rp.puntos_totales 
            ELSE 0 
          END
        ), 0) as puntos_jornada
      FROM users_liga ul
      JOIN users u ON ul.id_user = u.id
      LEFT JOIN rendimiento_partido rp 
        ON rp.id_user = ul.id_user
      LEFT JOIN partidos p 
        ON rp.id_partido = p.id_partido
        AND p.id_liga = ul.id_liga
        AND p.jornada = $2
        AND p.estado = 'finalizado'
        AND p.fecha_partido + interval '70 minutes' <= NOW()
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

// Obtener el estado de una jornada
router.get('/:id_liga/estado-jornada/:jornada', verifyToken, async (req, res) => {
  const { id_liga, jornada } = req.params;

  try {
    const result = await db.query(`
      SELECT
        COUNT(*) AS total_partidos,

        COUNT(*) FILTER (
          WHERE fecha_partido <= NOW()
        ) AS partidos_iniciados,

        COUNT(*) FILTER (
          WHERE estado = 'finalizado'
        ) AS partidos_simulados,

        COUNT(*) FILTER (
          WHERE estado = 'finalizado'
            AND fecha_partido + interval '70 minutes' <= NOW()
        ) AS partidos_visibles,

        BOOL_AND(
          estado = 'finalizado'
          AND fecha_partido + interval '70 minutes' <= NOW()
        ) AS jornada_finalizada_visible,

        BOOL_AND(premios_pagados = true) AS premios_pagados,

        MIN(fecha_partido) AS empieza_en,
        MAX(fecha_partido + interval '70 minutes') AS termina_visible_en

      FROM partidos
      WHERE id_liga = $1
        AND jornada = $2
    `, [id_liga, jornada]);

    const estado = result.rows[0];

    let estado_jornada = 'no_iniciada';

    if (Number(estado.partidos_iniciados) > 0 && !estado.jornada_finalizada_visible) {
      estado_jornada = 'en_curso';
    }

    if (estado.jornada_finalizada_visible) {
      estado_jornada = 'finalizada';
    }

    res.json({
      jornada: Number(jornada),
      estado_jornada,
      total_partidos: Number(estado.total_partidos || 0),
      partidos_iniciados: Number(estado.partidos_iniciados || 0),
      partidos_simulados: Number(estado.partidos_simulados || 0),
      partidos_visibles: Number(estado.partidos_visibles || 0),
      premios_pagados: estado.premios_pagados === true,
      empieza_en: estado.empieza_en,
      termina_visible_en: estado.termina_visible_en
    });

  } catch (err) {
    console.error('Error obteniendo estado de jornada:', err);
    res.status(500).json({ message: 'Error obteniendo estado de jornada' });
  }
});

// Terminar/Reiniciar Liga con opciones
router.post('/:id_liga/reset', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
  const { id_liga } = req.params;

  const {
    borrarPuntos,
    borrarJugadores,
    borrarJornadas,
    borrarDinero,
    borrarMensajes
  } = req.body;

  try {
    await db.query('BEGIN');

    // 1. Borrar todo lo relacionado con jornadas/partidos
    if (borrarJornadas) {
      await db.query(`
        DELETE FROM rendimiento_partido 
        WHERE id_partido IN (
          SELECT id_partido 
          FROM partidos 
          WHERE id_liga = $1
        )
      `, [id_liga]);

      await db.query(`
        DELETE FROM eventos_partido 
        WHERE id_partido IN (
          SELECT id_partido 
          FROM partidos 
          WHERE id_liga = $1
        )
      `, [id_liga]);

      await db.query(`
        DELETE FROM alineaciones_jornada 
        WHERE id_liga = $1
      `, [id_liga]);

      await db.query(`
        DELETE FROM partidos 
        WHERE id_liga = $1
      `, [id_liga]);
    }

    // 2. Resetear puntos de usuarios de esa liga
    if (borrarPuntos) {
      await db.query(`
        UPDATE users_liga 
        SET puntos = 0 
        WHERE id_liga = $1
      `, [id_liga]);
    }

    // 3. Resetear dinero
    if (borrarDinero) {
      await db.query(`
        UPDATE users_liga 
        SET dinero = 0 
        WHERE id_liga = $1
      `, [id_liga]);
    }

    // 4. Borrar jugadores y mercado
    if (borrarJugadores) {
      await db.query(`
        DELETE FROM futbolista_user_liga 
        WHERE id_liga = $1
      `, [id_liga]);

      await db.query(`
        DELETE FROM pujas 
        WHERE id_liga = $1
      `, [id_liga]);

      await db.query(`
        DELETE FROM mercado_liga 
        WHERE id_liga = $1
      `, [id_liga]);

      await db.query(`
        DELETE FROM historial_transferencias 
        WHERE id_liga = $1
      `, [id_liga]);

      await db.query(`
        DELETE FROM ofertas_privadas 
        WHERE id_liga = $1
      `, [id_liga]);
    }

    // 5. Borrar mensajes
    if (borrarMensajes) {
      await db.query(`
        DELETE FROM chat_general 
        WHERE id_liga = $1
      `, [id_liga]);

      await db.query(`
        DELETE FROM mensajes_privados 
        WHERE id_liga = $1
      `, [id_liga]);

      await db.query(`
        DELETE FROM ofertas_privadas 
        WHERE id_liga = $1
      `, [id_liga]);
    }

    // 6. Dejar la liga como inactiva y limpiar configuración de temporada
    await db.query(`
      UPDATE ligas
      SET 
        temporada_estado = 'inactiva',
        dinero_inicial = NULL,
        dar_plantilla_inicial = false,
        fecha_inicio_temporada = NULL,
        fecha_fin_temporada = NOW(),
        reset_automatico_en = NULL
      WHERE id_liga = $1
    `, [id_liga]);

    // 7. Limpiar formación y alineaciones activas de los usuarios
    await db.query(`
      UPDATE users_liga
      SET formacion = NULL
      WHERE id_liga = $1
    `, [id_liga]);

    await db.query('COMMIT');

    res.json({
      message: 'Liga reiniciada correctamente. La temporada queda inactiva y lista para configurarse de nuevo.'
    });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error('Error al reiniciar la liga:', err);
    res.status(500).json({ error: 'Error al reiniciar la liga' });
  }
});


// --- RUTAS DE MERCADO  ---
// Ver mercado de la liga
mercadoRouter.get('/:id_liga', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const idUser = req.user.id;

  try {
    const mercadoActual = await db.query(`
      SELECT fecha_generacion 
      FROM mercado_liga 
      WHERE id_liga = $1 
      LIMIT 1
    `, [id_liga]);

    const mercado = await db.query(`
      -- PARTE 1: JUGADORES DEL MERCADO DEL SISTEMA
      -- Aquí sí excluimos Real Trébol FC para que los ultras no salgan libres en mercado
      SELECT 
        f.id_futbolista,
        f.nombre,
        f.posicion,
        f.equipo,
        f.media,
        f.precio as precio,
        NULL::int as id_vendedor,
        NULL::text as vendedor_name,
        CASE WHEN p.id_user IS NOT NULL THEN true ELSE false END as pujado_por_mi,
        COALESCE(p.monto, 0) as mi_puja_actual,
        f.imagen,
        f.ataque,
        f.defensa,
        f.parada,
        f.pase,
        f.tipo_carta,
        f.codigo_habilidad,
        f.descripcion
      FROM mercado_liga ml
      JOIN futbolistas f ON f.id_futbolista = ml.id_futbolista
      LEFT JOIN pujas p 
        ON p.id_futbolista = f.id_futbolista 
        AND p.id_liga = $1 
        AND p.id_user = $2
      WHERE ml.id_liga = $1 
        AND f.equipo != 'Real Trébol FC'

      UNION ALL

      -- PARTE 2: JUGADORES PUESTOS EN VENTA POR USUARIOS
      -- Aquí NO excluimos Real Trébol FC, porque un usuario sí puede vender un ultra
      SELECT 
        f.id_futbolista,
        f.nombre,
        f.posicion,
        f.equipo,
        f.media,
        ful.precio_venta as precio,
        ful.id_user as id_vendedor,
        u.username as vendedor_name,
        false as pujado_por_mi,
        0 as mi_puja_actual,
        f.imagen,
        f.ataque,
        f.defensa,
        f.parada,
        f.pase,
        f.tipo_carta,
        f.codigo_habilidad,
        f.descripcion
      FROM futbolista_user_liga ful
      JOIN futbolistas f ON f.id_futbolista = ful.id_futbolista
      JOIN users u ON u.id = ful.id_user
      WHERE ful.id_liga = $1 
        AND ful.en_venta = true
    `, [id_liga, idUser]);

    const fechaGen = mercadoActual.rows.length 
      ? mercadoActual.rows[0].fecha_generacion 
      : new Date();

    res.json({
      jugadores: mercado.rows,
      fecha_generacion: fechaGen
    });

  } catch (err) {
    console.error('Error obteniendo mercado:', err);
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
  const { id_liga, id_futbolista, id_vendedor } = req.body;
  const idComprador = req.user.id;

  if (!id_liga || !id_futbolista || !id_vendedor) {
    return res.status(400).json({ message: 'Datos incompletos' });
  }

  if (Number(idComprador) === Number(id_vendedor)) {
    return res.status(400).json({ message: 'No puedes comprar tu propio jugador' });
  }

  try {
    await db.query('BEGIN');

    const ventaRes = await db.query(`
      SELECT 
        ful.precio_venta,
        f.nombre
      FROM futbolista_user_liga ful
      JOIN futbolistas f ON f.id_futbolista = ful.id_futbolista
      WHERE ful.id_liga = $1
        AND ful.id_user = $2
        AND ful.id_futbolista = $3
        AND ful.en_venta = true
      FOR UPDATE
    `, [id_liga, id_vendedor, id_futbolista]);

    if (ventaRes.rows.length === 0) {
      throw new Error('El jugador ya no está en venta');
    }

    const precio = Number(ventaRes.rows[0].precio_venta);

    if (!precio || precio <= 0) {
      throw new Error('Precio de venta no válido');
    }

    const compradorRes = await db.query(`
      SELECT dinero
      FROM users_liga
      WHERE id_liga = $1 
        AND id_user = $2
      FOR UPDATE
    `, [id_liga, idComprador]);

    if (compradorRes.rows.length === 0) {
      throw new Error('No perteneces a esta liga');
    }

    if (Number(compradorRes.rows[0].dinero) < precio) {
      throw new Error('No tienes suficiente dinero');
    }

    await db.query(`
      UPDATE users_liga 
      SET dinero = dinero - $1 
      WHERE id_user = $2 
        AND id_liga = $3
    `, [precio, idComprador, id_liga]);

    await db.query(`
      UPDATE users_liga 
      SET dinero = dinero + $1 
      WHERE id_user = $2 
        AND id_liga = $3
    `, [precio, id_vendedor, id_liga]);

    await db.query(`
      UPDATE futbolista_user_liga 
      SET 
        id_user = $1,
        en_venta = false,
        precio_venta = 0,
        es_titular = false,
        hueco_plantilla = NULL
      WHERE id_user = $2 
        AND id_liga = $3 
        AND id_futbolista = $4
    `, [idComprador, id_vendedor, id_liga, id_futbolista]);

    await db.query(`
      UPDATE ofertas_privadas
      SET estado = 'caducada'
      WHERE id_liga = $1
        AND id_futbolista = $2
        AND estado = 'pendiente'
    `, [id_liga, id_futbolista]);

    await db.query(`
      INSERT INTO historial_transferencias 
      (id_liga, id_futbolista, id_vendedor, id_comprador, monto, tipo)
      VALUES ($1, $2, $3, $4, $5, 'compra_usuario')
    `, [id_liga, id_futbolista, id_vendedor, idComprador, precio]);

    await db.query('COMMIT');

    res.json({ message: 'Fichaje realizado con éxito' });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error('Error en compra directa:', err);
    res.status(400).json({ message: err.message || 'Error en la transacción' });
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


// SOBRES
// Abrir sobre NORMAL 
router.post('/:id_liga/tienda/abrir-normal', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const id_user = req.user.id;
  const precioSobre = 5000000;

  try {
    await db.query('BEGIN');

    // Comprobamos si tiene dinero
    const userRes = await db.query('SELECT dinero FROM users_liga WHERE id_liga = $1 AND id_user = $2', [id_liga, id_user]);
    if (userRes.rows.length === 0 || Number(userRes.rows[0].dinero) < precioSobre) {
      throw new Error('No tienes suficientes Tc para este sobre.');
    }

    // Tiramos los dados de la probabilidad 
    const tirada = Math.random() * 100;
    let minMedia = 0;
    let maxMedia = 99;

    if (tirada < 60) { 
      // 60% Bronce
      minMedia = 60; maxMedia = 69;
    } else if (tirada < 85) { 
      // 25% Plata
      minMedia = 70; maxMedia = 79;
    } else if (tirada < 98) { 
      // 13% Oro
      minMedia = 80; maxMedia = 89;
    } else { 
      // 2% Diamante
      minMedia = 90; maxMedia = 95;
    }

    // Buscamos un jugador aleatorio en ese rango de media que esté libre 
    // Se añade un jugador que no lo tenga ningún usuario ni esté en el mercado
    let jugadorRes = await db.query(`
      SELECT * FROM futbolistas 
      WHERE media >= $1 AND media <= $2 
      AND tipo_carta = 'normal'
      AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $3)
      AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $3)
      ORDER BY RANDOM() LIMIT 1
    `, [minMedia, maxMedia, id_liga]);

    // Sistema de seguridad: ¿Qué pasa si ya no quedan libres de esa categoría? 
    if (jugadorRes.rows.length === 0) {
      jugadorRes = await db.query(`
        SELECT * FROM futbolistas 
        WHERE tipo_carta = 'normal'
        AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $1)
        AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $1)
        ORDER BY RANDOM() LIMIT 1
      `, [id_liga]);
      
      if (jugadorRes.rows.length === 0) {
        throw new Error('¡Ya no quedan jugadores libres en esta liga!');
      }
    }

    const jugadorTocado = jugadorRes.rows[0];

    // Cobramos el dinero
    await db.query('UPDATE users_liga SET dinero = dinero - $1 WHERE id_liga = $2 AND id_user = $3', [precioSobre, id_liga, id_user]);

    // Le damos el jugador
    await db.query('INSERT INTO futbolista_user_liga (id_user, id_liga, id_futbolista, en_venta, precio_venta) VALUES ($1, $2, $3, false, 0)', 
      [id_user, id_liga, jugadorTocado.id_futbolista]);

    await db.query('COMMIT');
    
    // Devolvemos el jugador para la animación
    res.json({ mensaje: 'Sobre abierto con éxito', jugador: jugadorTocado });

  } catch (err) {
    // Si algo falla, cancelamos todo para que no pierda dinero
    await db.query('ROLLBACK'); 
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

    // Comprobamos si tiene dinero
    const userRes = await db.query('SELECT dinero FROM users_liga WHERE id_liga = $1 AND id_user = $2', [id_liga, id_user]);
    if (userRes.rows.length === 0 || Number(userRes.rows[0].dinero) < precioSobre) {
      throw new Error('No tienes suficientes Tc para este sobre.');
    }

    // Tiramos los dados 
    const tirada = Math.random() * 100;
    let minMedia = 0;
    let maxMedia = 99;

    if (tirada < 70) { 
      // 70% Bronce
      minMedia = 60; maxMedia = 69;
    } else if (tirada < 90) { 
      // 20% Plata
      minMedia = 70; maxMedia = 79;
    } else if (tirada < 99) { 
      // 9% Oro
      minMedia = 80; maxMedia = 89;
    } else { 
      // 1% Diamante 
    
      minMedia = 90; maxMedia = 95;
    }

    // Buscamos el jugador filtrando por posición
    let jugadorRes = await db.query(`
      SELECT * FROM futbolistas 
      WHERE media >= $1 AND media <= $2 
      AND tipo_carta = 'normal'
      AND TRIM(UPPER(posicion)) = $3
      AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $4)
      AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $4)
      ORDER BY RANDOM() LIMIT 1
    `, [minMedia, maxMedia, posicion, id_liga]);

    // Fallback de seguridad: Si no quedan de esa media, le damos cualquiera de esa posición
    if (jugadorRes.rows.length === 0) {
      jugadorRes = await db.query(`
        SELECT * FROM futbolistas 
        WHERE tipo_carta = 'normal'
        AND TRIM(UPPER(posicion)) = $1
        AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $2)
        AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $2)
        ORDER BY RANDOM() LIMIT 1
      `, [posicion, id_liga]);
      
      if (jugadorRes.rows.length === 0) {
        throw new Error(`¡Ya no quedan jugadores libres en la posición ${posicion}!`);
      }
    }

    const jugadorTocado = jugadorRes.rows[0];

    // Cobramos los 10 Millones
    await db.query('UPDATE users_liga SET dinero = dinero - $1 WHERE id_liga = $2 AND id_user = $3', [precioSobre, id_liga, id_user]);

    // Damos el jugador
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

// Abrir Sobre ESPECIAL 
router.post('/:id_liga/tienda/abrir-especial', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const id_user = req.user.id;
  const precioSobre = 20000000;

  try {
    await db.query('BEGIN');

    // Validar saldo
    const userRes = await db.query('SELECT dinero FROM users_liga WHERE id_liga = $1 AND id_user = $2', [id_liga, id_user]);
    if (userRes.rows.length === 0 || Number(userRes.rows[0].dinero) < precioSobre) {
      throw new Error('No tienes suficientes Tc. El sobre cuesta 25 Millones.');
    }

    // Tirada principal, puede tocar o normal o especial
    // 20% de probabilidad de ser Especial
    const esEspecial = (Math.random() * 100) < 20; 

    let minMedia = 0;
    let maxMedia = 99;
    let tipoCarta = esEspecial ? 'especial' : 'normal';

    // Tirada secundaria, el nivel de la carta
    const tiradaNivel = Math.random() * 100;

    if (esEspecial) {
      // Porcentajes para Cartas ESPECIALES

      // 70% Especial Nivel 1
      if (tiradaNivel < 70) { minMedia = 77; maxMedia = 82; } 
      // 25% Especial Nivel 2
      else if (tiradaNivel < 95) { minMedia = 83; maxMedia = 88; } 
      // 5% Especial Nivel 3
      else { minMedia = 89; maxMedia = 95; } 
    } else {
      // Porcentajes mejorados para Cartas NORMALES

      // 40% Bronce
      if (tiradaNivel < 40) { minMedia = 60; maxMedia = 69; } 
      // 35% Plata
      else if (tiradaNivel < 75) { minMedia = 70; maxMedia = 79; }  
      // 20% Oro 
      else if (tiradaNivel < 95) { minMedia = 80; maxMedia = 89; } 
      // 5% Diamante
      else { minMedia = 90; maxMedia = 95; }  
    }

    // Buscar el jugador con esas condiciones que esté libre
    let jugadorRes = await db.query(`
      SELECT * FROM futbolistas 
      WHERE media >= $1 AND media <= $2 
      AND tipo_carta = $3
      AND id_futbolista NOT IN (SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $4)
      AND id_futbolista NOT IN (SELECT id_futbolista FROM mercado_liga WHERE id_liga = $4)
      ORDER BY RANDOM() LIMIT 1
    `, [minMedia, maxMedia, tipoCarta, id_liga]);

    // Fallback por si no quedan jugadores de ese nivel en esa categoría
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

    // Cobrar los 20 Millones
    await db.query('UPDATE users_liga SET dinero = dinero - $1 WHERE id_liga = $2 AND id_user = $3', [precioSobre, id_liga, id_user]);

    // Entregar el jugador
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

// Abrir sobre ULTRA 
router.post('/:id_liga/tienda/abrir-ultra', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const id_user = req.user.id;
  const precioSobre = 30000000; 

  try {
    await db.query('BEGIN');

    // Verificar si el usuario tiene la pasta
    const userRes = await db.query(
      'SELECT dinero FROM users_liga WHERE id_liga = $1 AND id_user = $2',
      [id_liga, id_user]
    );

    if (userRes.rows.length === 0 || Number(userRes.rows[0].dinero) < precioSobre) {
      throw new Error('Fondos insuficientes para el Sobre Ultra (30M Tc).');
    }

    // Tirada para determinar la rareza de la carta
    const suerte = Math.random() * 100;
    let tipoTocado = 'normal';
    
    if (suerte < 10) {
      tipoTocado = 'ultra'; 
    } else if (suerte < 30) {
      tipoTocado = 'especial';
    }

    // BUSCAR JUGADOR DISPONIBLE
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

    // Fallback, si no quedan cartas de esa rareza, bajamos un escalón
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

    // Cobrar y entregar
    await db.query(
      'UPDATE users_liga SET dinero = dinero - $1 WHERE id_liga = $2 AND id_user = $3',
      [precioSobre, id_liga, id_user]
    );

    await db.query(
      'INSERT INTO futbolista_user_liga (id_user, id_liga, id_futbolista) VALUES ($1, $2, $3)',
      [id_user, id_liga, crack.id_futbolista]
    );

    // Anuncio épico en el chat
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
    // Crear la oferta oficial en la tabla de negociaciones
    const ofertaRes = await db.query(`
      INSERT INTO ofertas_privadas (id_liga, id_futbolista, id_comprador, id_vendedor, monto)
      VALUES ($1, $2, $3, $4, $5) RETURNING id_oferta
    `, [id_liga, id_futbolista, id_comprador, id_destinatario, monto]);
    const id_oferta = ofertaRes.rows[0].id_oferta;

    // Obtener el nombre del jugador para el asunto
    const futRes = await db.query('SELECT nombre FROM futbolistas WHERE id_futbolista = $1', [id_futbolista]);
    const nombreJugador = futRes.rows[0].nombre;

    // Crear el mensaje en el buzón con el formato de oferta
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

// Aceptar la oferta (hace el intercambio de jugador y dinero automático)
router.post('/:id_liga/ofertas/aceptar', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const { id_oferta, id_mensaje } = req.body;
  const id_vendedor = req.user.id;

  try {
    await db.query('BEGIN'); 

    // 1Buscar la oferta y validarla
    const ofertaRes = await db.query("SELECT * FROM ofertas_privadas WHERE id_oferta = $1 AND estado = 'pendiente'", [id_oferta]);
    if (ofertaRes.rows.length === 0) throw new Error('La oferta ya no es válida o ha caducado.');
    const oferta = ofertaRes.rows[0];

    // Comprobar que el comprador tiene dinero 
    const compradorRes = await db.query('SELECT dinero FROM users_liga WHERE id_liga = $1 AND id_user = $2', [id_liga, oferta.id_comprador]);
    if (compradorRes.rows[0].dinero < oferta.monto) throw new Error('El comprador ya no tiene dinero suficiente.');

    // Mover el dinero 
    await db.query('UPDATE users_liga SET dinero = dinero - $1 WHERE id_liga = $2 AND id_user = $3', [oferta.monto, id_liga, oferta.id_comprador]);
    await db.query('UPDATE users_liga SET dinero = dinero + $1 WHERE id_liga = $2 AND id_user = $3', [oferta.monto, id_liga, id_vendedor]);

    // Traspasar al jugador
    await db.query(`
      UPDATE futbolista_user_liga 
      SET id_user = $1, en_venta = false, precio_venta = 0 
      WHERE id_futbolista = $2 AND id_liga = $3
    `, [oferta.id_comprador, oferta.id_futbolista, id_liga]);

    // Marcar oferta como aceptada y mensaje como procesado
    await db.query("UPDATE ofertas_privadas SET estado = 'aceptada' WHERE id_oferta = $1", [id_oferta]);
    await db.query("UPDATE mensajes_privados SET leido = true, tipo = 'texto', contenido = contenido || '\n\n✅ OFERTA ACEPTADA' WHERE id_privado = $1", [id_mensaje]);

    // Le mandamos un mensaje automático al comprador diciendo que es suyo
    await db.query(`
      INSERT INTO mensajes_privados (id_liga, id_remitente, id_destinatario, tipo, asunto, contenido)
      VALUES ($1, $2, $3, 'texto', '¡Trato cerrado!', 'Tu oferta de ${oferta.monto} Tc ha sido aceptada. El jugador ya está en tu plantilla.')
    `, [id_liga, id_vendedor, oferta.id_comprador]);

    //Guardamos todo y sino hacemos rollback
    await db.query('COMMIT'); 
    res.json({ message: '¡Trato cerrado! Dinero y jugador intercambiados.' });
  } catch (err) {
    await db.query('ROLLBACK');
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


// --- RUTAS DE OBTENER DATOS ---
// Obtener la CLASIFICACIÓN GENERAL de la Liga
router.get('/:id_liga/clasificacion', verifyToken, async (req, res) => {
  const { id_liga } = req.params;

  try {
    const result = await db.query(`
      WITH jornadas_finalizadas AS (
        SELECT id_liga, jornada
        FROM partidos
        WHERE id_liga = $1
        GROUP BY id_liga, jornada
        HAVING BOOL_AND(
          estado = 'finalizado'
          AND fecha_partido + interval '70 minutes' <= NOW()
        )
      ),
      puntos_visibles AS (
        SELECT 
          rp.id_user,
          SUM(rp.puntos_totales) AS puntos
        FROM rendimiento_partido rp
        JOIN partidos p ON p.id_partido = rp.id_partido
        JOIN jornadas_finalizadas jf
          ON jf.id_liga = p.id_liga
          AND jf.jornada = p.jornada
        WHERE p.id_liga = $1
        GROUP BY rp.id_user
      )
      SELECT 
        u.id,
        u.username,
        u.avatar,
        ul.rol,
        ul.dinero AS presupuesto,

        COALESCE(pv.puntos, 0) AS puntos,

        (
          SELECT COUNT(*) 
          FROM futbolista_user_liga ful 
          WHERE ful.id_user = u.id 
            AND ful.id_liga = $1
        ) AS total_jugadores

      FROM users_liga ul
      JOIN users u ON ul.id_user = u.id
      LEFT JOIN puntos_visibles pv ON pv.id_user = ul.id_user

      WHERE ul.id_liga = $1

      ORDER BY puntos DESC, u.username ASC
    `, [id_liga]);

    res.json(result.rows);
  } catch(err) {
    console.error(err);
    res.status(500).json({ message: 'Error cargando clasificación general' });
  }
});

// Obtener lista de todos los mánagers de la liga (Para el desplegable)
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

// Obtener los puntos de un Mánager concreto en una Jornada concreta
router.get('/:id_liga/puntos-jornada', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const { id_manager, jornada } = req.query;

  if (!id_manager || !jornada) {
    return res.status(400).json({ message: 'Manager y jornada requeridos' });
  }

  try {
    const jornadaFinalizadaRes = await db.query(`
      SELECT 
        COUNT(*) > 0 AS existe_jornada,
        BOOL_AND(
          estado = 'finalizado' 
          AND fecha_partido + interval '70 minutes' <= NOW()
        ) AS jornada_visible_finalizada
      FROM partidos
      WHERE id_liga = $1
        AND jornada = $2
    `, [parseInt(id_liga), parseInt(jornada)]);

    const estadoJornada = jornadaFinalizadaRes.rows[0] || {};
    const jornadaVisibleFinalizada = estadoJornada.jornada_visible_finalizada === true;

    const query = `
      WITH partidos_visibles AS (
        SELECT id_partido
        FROM partidos
        WHERE id_liga = $1
          AND jornada = $3
          AND estado = 'finalizado'
          AND fecha_partido + interval '70 minutes' <= NOW()
      ),
      puntos_por_jugador AS (
        SELECT 
          rp.id_user,
          rp.id_futbolista,
          rp.hueco_plantilla,
          SUM(rp.puntos_totales) AS puntos,
          SUM(rp.goles) AS goles,
          SUM(rp.asistencias) AS asistencias,
          SUM(rp.amarillas) AS amarillas,
          SUM(rp.rojas) AS rojas,
          MAX(rp.nota_base) AS nota_base
        FROM rendimiento_partido rp
        JOIN partidos_visibles pv ON pv.id_partido = rp.id_partido
        WHERE rp.id_user = $2
        GROUP BY rp.id_user, rp.id_futbolista, rp.hueco_plantilla
      )
      SELECT 
        aj.hueco_plantilla,
        aj.id_futbolista,
        aj.es_hueco_vacio,
        aj.nombre_snapshot,
        aj.posicion_snapshot,
        aj.media_snapshot,
        aj.tipo_carta_snapshot,
        aj.codigo_habilidad_snapshot,

        CASE
          WHEN aj.es_hueco_vacio = true THEN 'Hueco vacío'
          ELSE aj.nombre_snapshot
        END AS nombre,

        CASE
          WHEN aj.es_hueco_vacio = true THEN '-'
          ELSE aj.posicion_snapshot
        END AS posicion,

        COALESCE(aj.media_snapshot, 0) AS valor,

        CASE 
          WHEN aj.hueco_plantilla = 'hueco-12' THEN NULL
          WHEN aj.es_hueco_vacio = true THEN COALESCE(ppj.puntos, -3)
          WHEN ppj.puntos IS NOT NULL THEN ppj.puntos
          WHEN $4::boolean = true THEN 0
          ELSE NULL
        END AS puntos,

        COALESCE(ppj.goles, 0) AS goles,
        COALESCE(ppj.asistencias, 0) AS asistencias,
        COALESCE(ppj.amarillas, 0) AS amarillas,
        COALESCE(ppj.rojas, 0) AS rojas,
        ppj.nota_base,

        CASE
          WHEN aj.hueco_plantilla = 'hueco-12' THEN 'habilidad'
          WHEN aj.es_hueco_vacio = true THEN 'hueco_vacio'
          WHEN ppj.puntos IS NOT NULL THEN 'puntuado'
          WHEN $4::boolean = true THEN 'no_jugo'
          ELSE 'pendiente'
        END AS estado_puntuacion

      FROM alineaciones_jornada aj
      LEFT JOIN puntos_por_jugador ppj
        ON ppj.id_user = aj.id_user
        AND (
          (ppj.id_futbolista = aj.id_futbolista)
          OR (
            ppj.hueco_plantilla = aj.hueco_plantilla 
            AND aj.es_hueco_vacio = true
          )
        )
      WHERE aj.id_liga = $1
        AND aj.id_user = $2
        AND aj.jornada = $3
      ORDER BY 
        CASE 
          WHEN aj.hueco_plantilla = 'hueco-12' THEN 12
          ELSE CAST(REPLACE(aj.hueco_plantilla, 'hueco-', '') AS integer)
        END ASC;
    `;

    const result = await db.query(query, [
      parseInt(id_liga),
      parseInt(id_manager),
      parseInt(jornada),
      jornadaVisibleFinalizada
    ]);

    res.json(result.rows);
  } catch (err) {
    console.error("Error en puntos-jornada:", err);
    res.status(500).json({ message: 'Error cargando puntos' });
  }
});

// Obtener la clasificación real de los clubes (Athletic Hullera, etc.)
router.get('/:id_liga/clasificacion-clubes', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  try {
    const query = `
      WITH Equipos AS (
        SELECT DISTINCT equipo 
        FROM futbolistas 
        WHERE equipo != 'Real Trébol FC'
      ),
      Resultados AS (
        SELECT 
          equipo_local AS equipo, 
          goles_local AS gf, 
          goles_visitante AS gc, 
          CASE WHEN goles_local > goles_visitante THEN 1 ELSE 0 END AS pg, 
          CASE WHEN goles_local = goles_visitante THEN 1 ELSE 0 END AS pe, 
          CASE WHEN goles_local < goles_visitante THEN 1 ELSE 0 END AS pp, 
          CASE 
            WHEN goles_local > goles_visitante THEN 3 
            WHEN goles_local = goles_visitante THEN 1 
            ELSE 0 
          END AS pts
        FROM partidos 
        WHERE id_liga = $1 
          AND estado = 'finalizado'
          AND fecha_partido + interval '70 minutes' <= NOW()

        UNION ALL

        SELECT 
          equipo_visitante AS equipo, 
          goles_visitante AS gf, 
          goles_local AS gc, 
          CASE WHEN goles_visitante > goles_local THEN 1 ELSE 0 END AS pg, 
          CASE WHEN goles_visitante = goles_local THEN 1 ELSE 0 END AS pe, 
          CASE WHEN goles_visitante < goles_local THEN 1 ELSE 0 END AS pp, 
          CASE 
            WHEN goles_visitante > goles_local THEN 3 
            WHEN goles_visitante = goles_local THEN 1 
            ELSE 0 
          END AS pts
        FROM partidos 
        WHERE id_liga = $1 
          AND estado = 'finalizado'
          AND fecha_partido + interval '70 minutes' <= NOW()
      )
      SELECT 
        e.equipo, 
        COALESCE(COUNT(r.equipo), 0) AS pj, 
        COALESCE(SUM(r.pg), 0) AS pg, 
        COALESCE(SUM(r.pe), 0) AS pe, 
        COALESCE(SUM(r.pp), 0) AS pp, 
        COALESCE(SUM(r.gf), 0) AS gf, 
        COALESCE(SUM(r.gc), 0) AS gc, 
        COALESCE(SUM(r.gf) - SUM(r.gc), 0) AS dif, 
        COALESCE(SUM(r.pts), 0) AS puntos_totales
      FROM Equipos e
      LEFT JOIN Resultados r ON e.equipo = r.equipo
      GROUP BY e.equipo 
      ORDER BY puntos_totales DESC, dif DESC, gf DESC, e.equipo ASC;
    `;
    const clasificacion = await db.query(query, [id_liga]);
    res.json(clasificacion.rows);
  } catch(err) { 
    res.status(500).json({message: 'Error calculando la clasificación de los clubes'}); 
  }
});



// [=== CRONS ===]
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
const FRASES = {
  golesSolo: [
    "¡GOOOOOOOLAAAAAAAAAAAAAZO DE {goleador}! ¡Le pegó con el alma y la mandó a guardar!",
    "¡PERO QUÉ BARBARIDAD! {goleador} se inventa una jugada de otro planeta y la clava en la mismísima escuadra.",
    "¡Gooooooool! {goleador} huele sangre, roba en la frontal, recorta al portero y fusila sin piedad.",
    "¡Gooooooooool! Zapatazo nuclear de {goleador} que casi arranca la red de cuajo. ¡Qué potencia!",
    "¡GOL GOL GOL GOL! ¡Sáquenla si pueden! {goleador} define con una vaselina exquisita que deja a todo el estadio mudo.",
    "¡GOOOOOOOL! {goleador} arranca desde su casa, deja a tres rivales por el suelo y define como los dioses.",
    "¡GOLAZO! ¡Qué remate, por favor! {goleador} la engancha de volea y el balón entra pidiendo permiso.",
    "¡Gooooool! Error garrafal en la salida de balón, {goleador} intercepta y castiga el error. ¡Instinto asesino!",
    "¡GOOOOOOOL! ¡Se cae el estadio! Tiro libre directo de {goleador} que limpia las telarañas del arco.",
    "¡Gol de {goleador}! Entró al área como un búfalo, aguantó la embestida del central y definió cruzado. ¡Imparable!",
    "¡AY MI MADRE! ¡Díganle a {goleador} que esto es la vida real y no la Play! ¡Qué auténtica barbaridad de gol!",
    "¡GOLAZO HISTÓRICO! {goleador} coge la moto, mete la quinta marcha y define por debajo de las piernas del portero.",
    "¡RATATATATATA! ¡GOOOOL! {goleador} arma la pierna en una baldosa y saca un latigazo cruzado espectacular.",
    "¡GOOOOOOOL! ¡La picó! ¡Qué sangre fría! {goleador} se la levanta al portero con un toque de pura seda.",
    "¡Gooooool! ¡Zambombazo raso de {goleador} que se cuela ajustado a la cepa del poste! ¡Imparable!",
    "¡QUÉ ESCÁNDALO DE GOL! {goleador} baila sobre la línea de fondo, recorta hacia dentro y la clava en el ángulo.",
    "¡GOOOOOOOL! Se revuelve en el área, amaga el disparo, vuelve a amagar... ¡Y pum! {goleador} no perdona.",
    "¡Es el gol de la jornada! {goleador} empalma un rechace desde la frontal y el balón hace una parábola imposible.",
    "¡GOL! Trallazo seco y abajo de {goleador}. El portero se estiró pero eso iba teledirigido.",
    "¡GOOOOOOOL! ¡Sombrerito al defensa y volea a la red! {goleador} acaba de firmar una obra de arte para el museo."
  ],
  golesAsistencia: [
    "¡GOOOOOOOL! ¡Pero medio gol es de {asistente}! Qué escándalo de pase, {goleador} solo tuvo que empujarla.",
    "¡Gooooooool! Balón picadito, pura magia de {asistente}, y {goleador} empalma una volea de locos.",
    "¡GOL GOL GOL! Centro teledirigido con tiralíneas de {asistente} a la cabeza de {goleador}. ¡Martillazo a la red!",
    "¡GOLAZO! Pared de videoconsola entre {asistente} y {goleador}, taconazo incluido, que destroza a la defensa entera.",
    "¡Gol de {goleador}! Asistencia de cirujano de {asistente}, que vio un hueco donde solo había piernas rivales.",
    "¡Gooooool! {asistente} rompe líneas con un pase raso a la carrera de {goleador}, que define de primeras. ¡Fútbol total!",
    "¡GOL! Jugadón por la banda de {asistente}, pone el pase de la muerte y {goleador} entra con todo para reventar el balón.",
    "¡Gooooool! Triangulación perfecta. {asistente} asiste de tacón y {goleador} no perdona en el mano a mano.",
    "¡GOL! Saque de esquina sacado con veneno por {asistente} y {goleador} se eleva sobre las nubes para marcar.",
    "¡GOOOOOOOL! Pase largo, de 40 metros, de {asistente} al pecho de {goleador}, que controla y fusila al portero.",
    "¡GOLAZO! ¡Fútbol Champagne! {asistente} filtra un pase sin mirar y {goleador} define con el interior del pie.",
    "¡GOL GOL GOL! ¡Qué invento de {asistente}! Dejó sentada a la defensa con un recorte y le regaló el gol a {goleador}.",
    "¡GOOOOOL! Jugada ensayada de pizarra pura. La pone {asistente} al punto de penalti y {goleador} machaca sin piedad.",
    "¡Gooooool! Pase de cuchara precioso de {asistente} saltando la defensa, y {goleador} la engancha sin dejarla caer.",
    "¡QUÉ MARAVILLA! {asistente} caracolea en la banda, centra de rabona y {goleador} entra como un obús para empujarla."
  ],
  lesiones: [
    "🚑 ¡UFFFF! Qué mala pinta tiene eso... {jugador} se rompe en seco tras un mal giro. El estadio enmudece. Posible {lesion}.",
    "🚑 ¡No me lo puedo creer! {jugador} pisa mal y cae gritando de dolor. Entran las asistencias a toda prisa. Diagnóstico: {lesion}.",
    "🚑 ¡Drama en el terreno de juego! {jugador} sale en camilla tapándose la cara con la camiseta. Sufre {lesion}.",
    "🚑 ¡Qué lástima! {jugador} frena en seco en plena carrera de sprint y se tira al suelo. El fisio pide el cambio por {lesion}.",
    "🚑 Saltan las alarmas. Choque durísimo y {jugador} se lleva la peor parte. Abandona el campo cojeando visiblemente ({lesion}).",
    "🚑 Silencio sepulcral en la grada. {jugador} cae fulminado tocándose la rodilla. Pésimas noticias, parece {lesion}.",
    "🚑 Dura baja. {jugador} no puede seguir tras esa terrorífica caída. Se confirma {lesion} y no podrá continuar.",
    "🚑 ¡Se ha roto! Se lleva las manos a los isquiotibiales... {jugador} ha sentido un pinchazo brutal. Apunta a {lesion}.",
    "🚑 Terrible lance. {jugador} ha chocado rodilla con rodilla y pide el cambio al instante. Posible {lesion}.",
    "🚑 ¡Madre mía qué grito ha pegado! El estadio entero se ha callado. {jugador} no puede apoyar el pie tras sufrir {lesion}."
  ],
  cambios: [
      "🔄 Mueve el banquillo el míster. Abandona el terreno de juego {sale} y salta al césped {entra} con ganas de demostrar.",
      "🔄 ¡Cambio táctico! Se retira {sale} tras un gran desgaste físico y entra de refresco {entra}.",
      "🔄 Piernas frescas para el equipo. El entrenador da entrada a {entra} en sustitución de {sale}.",
      "🔄 ¡Aplausos en la grada! Despiden a {sale} por su esfuerzo y reciben con ánimos a {entra}.",
      "🔄 Sangre nueva al verde. {sale} deja su sitio a {entra}, buscando agitar el partido.",
      "🔄 Se produce la sustitución. Veremos qué aporta {entra}, que entra motivadísimo para darle descanso a {sale}.",
      "🔄 El míster busca soluciones en la pizarra. Se marcha {sale} y le toca el turno a {entra}.",
      "🔄 ¡Agita el árbol el técnico! {entra} pisa el césped chocando las manos con {sale}."
    ],
    cambiosOfensivos: [
      "🔄 ¡A por el partido! El míster ve que van perdiendo y saca del campo a {sale} para meter más pólvora con {entra}.",
      "🔄 Cambio a la desesperada. {sale} deja el césped y entra {entra} con la misión clara de remontar esto."
    ],
    cambiosCastigo: [
      "🔄 El técnico no está nada contento con el partido de {sale} y lo cambia de inmediato. Entra {entra} en su lugar.",
      "🔄 Cambio preventivo del entrenador. Saca a {sale}, que estaba jugando con fuego tras la amarilla, y da entrada a {entra}."
    ],
  amarillas: [
    "🟨 ¡Menudo hachazo! El árbitro le saca la amarilla a {jugador} y da gracias que no sea de otro color.",
    "🟨 Amarilla clarísima para {jugador}. Se tiró con los tacos por delante a cortar un contragolpe letal.",
    "🟨 ¡Se calentó el partido! Tarjeta amarilla a {jugador} por encararse con el colegiado de forma muy agresiva.",
    "🟨 El árbitro no perdona una. Amarilla para {jugador} tras un plantillazo feísimo en el centro del campo.",
    "🟨 Amarilla para {jugador}. Agarrón descarado por detrás, cortando la jugada. De manual de fútbol.",
    "🟨 Tarjeta amarilla para {jugador}. Falta táctica muy dura para frenar la transición rival.",
    "🟨 ¡Ojo que saltan chispas! Amarilla a {jugador} tras un encontronazo durísimo. El árbitro pone orden.",
    "🟨 ¡Le ha dado hasta en el carné de identidad! Amarilla para {jugador} por una entrada a destiempo.",
    "🟨 Cuidado con {jugador}... Se ha llevado la amarilla por protestar airadamente al linier.",
    "🟨 Tarjeta amarilla a {jugador}. Obstrucción clarísima cuando el delantero ya se iba directo a la portería.",
    "🟨 Falta reiterativa. El árbitro ya le había avisado y a {jugador} no le queda otra que ver la cartulina amarilla.",
    "🟨 Plancha durísima a ras de suelo. Amarilla indiscutible para {jugador}, que acepta la tarjeta sin rechistar."
  ],
  rojas: [
    "🟥 ¡A LA DUCHA! Roja directa a {jugador}. ¡Entrada criminal a la altura de la rodilla que casi lo parte en dos!",
    "🟥 ¡Se le cruzaron los cables! {jugador} suelta un codazo en la cara y el árbitro lo expulsa sin miramientos.",
    "🟥 Roja inapelable para {jugador}. Era el último hombre y derribó al delantero cuando ya encaraba al portero.",
    "🟥 ¡ESCÁNDALO! ¡El árbitro le saca la roja a {jugador}! Tremenda agresión sin balón que deja a su equipo hundido.",
    "🟥 ¡Roja directa! {jugador} pierde los papeles por completo y suelta una patada a destiempo. ¡A la calle!",
    "🟥 ¡No me lo puedo creer, expulsado! Doble amarilla absurda de {jugador} en un minuto. ¡Deja a los suyos con 10 hombres!",
    "🟥 ¡Expulsión clarísima! {jugador} salva un gol cantado usando las manos cual portero. ¡Penalti y roja!",
    "🟥 ¡Terrible, apocalíptico! Entrada voladora con los dos pies por delante de {jugador}. La roja se queda corta.",
    "🟥 Se formó la tangana... ¡Y el árbitro expulsa a {jugador} por un manotazo al rival! ¡Cuidado que se lía!",
    "🟥 Incomprensible lo de {jugador}. Aplausos irónicos en la cara del árbitro tras una amarilla y... ¡Roja directa!"
  ],
  rellenoParadas: [
    "🧤 ¡SANTO CIELO QUÉ PARADÓN! El portero vuela como un superhéroe para sacarle el gol a {atacante} en la misma escuadra.",
    "🧤 ¡Era gol cantado! Pero el arquero saca un pie antológico a bocajarro ante el disparo de {atacante}. ¡Impresionante!",
    "🧤 ¡Milagro en el área chica! {atacante} fusila a dos metros y el meta la saca con unos reflejos felinos.",
    "🧤 ¡Gatito puro! Vuelo sin motor para desviar con la punta de los dedos el trallazo lejano de {atacante}.",
    "🧤 ¡El muro bajo palos! Atrapa el portero en dos tiempos el remate mordido pero envenenado de {atacante}.",
    "🧤 ¡Increíble! Doble intervención del meta: primero le saca el tiro a {atacante} y luego tapa el rebote con el pecho.",
    "🧤 ¡La parada de la temporada! {atacante} remató de cabeza a quemarropa y el portero sacó una mano de puro milagro.",
    "🧤 ¡Seguridad absoluta! {atacante} intenta sorprender desde fuera del área pero el arquero bloca el balón sin dar rechace.",
    "🧤 ¡Provindencial! El meta sale achicando espacios y se hace enorme ante la internada letal de {atacante}.",
    "🧤 ¡Paradón con la cara! {atacante} fusila pero el portero pone el cuerpo entero y evita el gol jugándose el físico."
  ],
  rellenoPalos: [
    "🥅 ¡AL LARGUEEEEEERO! El misil de {atacante} hace temblar la portería. ¡Aún sigue vibrando el metal!",
    "🥅 ¡CRACK! El sonido del poste tras el tiro cruzado de {atacante} despierta a todo el estadio. ¡Qué cerca estuvo!",
    "🥅 Uyyyy... ¡Casi cae el estadio! El balón de {atacante} roza la madera y se marcha acariciando la red por fuera.",
    "🥅 ¡Por milímetros! {atacante} cruzó su disparo ante la salida del arquero y el balón lamió el poste izquierdo.",
    "🥅 ¡A las nubes! {atacante} lo intentó de volea tras un rechace, pero la mandó directamente al tercer anfiteatro.",
    "🥅 ¡Palo y fuera! Remate de cabeza imparable de {atacante} que se estrella en la cepa del poste derecho.",
    "🥅 ¡Falta de puntería! {atacante} se quedó solo ante el portero, pero quiso ajustar tanto que la mandó rozando la escuadra.",
    "🥅 ¡El poste salva al equipo! Tiro libre majestuoso de {atacante} que se estrella de lleno en la cruceta.",
    "🥅 Uyyyy... {atacante} intentó la vaselina por encima del portero pero el balón botó y se fue por encima del travesaño.",
    "🥅 ¡Pero cómo no ha entrado eso! Disparo a bocajarro de {atacante} que inexplicablemente choca contra el hierro."
  ],
  rellenoRegates: [
    "✨ ¡Por favor, qué escándalo! {atacante} hace una croqueta, le tira un caño al central y sale sonriendo.",
    "✨ {atacante} está absolutamente desatado. Bicicleta doble, freno, y deja a su marcador buscando la cadera por el suelo.",
    "✨ ¡Qué descaro, qué atrevimiento! {atacante} le hace un sombrero al defensor en una baldosa y sale jugando.",
    "✨ Espectacular eslalon de {atacante}, que coge la moto, deja sentados a tres rivales y se asoma al balcón del área.",
    "✨ Pura magia brasileña. {atacante} pisa el balón, recorta hacia dentro con una elástica y arranca los aplausos del público.",
    "✨ ¡Juega a otro deporte! Control orientado maravilloso de {atacante} que rompe dos líneas de presión de un solo toque.",
    "✨ ¡Le ha roto la cadera! {atacante} amaga con el tiro, frena en seco y el defensa pasa de largo derrapando.",
    "✨ Ruleta marsellesa en pleno centro del campo. ¡Qué clase, qué elegancia tiene {atacante} con el balón en los pies!",
    "✨ ¡Túnel mágico! {atacante} sale de la presión de dos rivales tirando un caño espectacular de tacón.",
    "✨ Qué jugada de {atacante}... Autopase rompiendo la línea, carrera imparable y regate en corto. ¡Pura fantasía!"
  ],
  rellenoDefensas: [
    "🛡️ ¡QUÉ CORTE! {defensor} se lanza a ras de hierba para salvar un gol seguro bajo palos. ¡Vale como un tanto!",
    "🛡️ Imperial, como un titán. {defensor} se cruza y le roba la cartera al delantero en el último suspiro de la jugada.",
    "🛡️ ¡Limpieza total! {defensor} mete la pierna en un cruce milimétrico dentro del área sin hacer falta. Cirugía pura.",
    "🛡️ Anticipación perfecta de {defensor}, que lee el pase entrelíneas, corta el peligro y sale jugando con la cabeza alta.",
    "🛡️ {defensor} se erige como un auténtico muro de hormigón armado y despeja de cabeza el bombardeo aéreo.",
    "🛡️ ¡Salvavidas! {defensor} se tira con todo al suelo para taponar un disparo a quemarropa que iba directo a la red.",
    "🛡️ ¡Aquí no se pasa! {defensor} aguanta la embestida del delantero rival, mete cuerpo y se queda con el esférico.",
    "🛡️ ¡Qué lectura de juego! {defensor} se anticipa al delantero, corta el contragolpe y apaga el fuego en su área.",
    "🛡️ Contundencia absoluta. {defensor} despeja un balón peligroso enviándolo directamente a la quinta gradería.",
    "🛡️ ¡Providencial {defensor}! Corrió como un guepardo hacia atrás para sacar en la línea de gol un balón que ya entraba."
  ],
  rellenoTransicion: [
    "👟 El partido entra en fase de ajedrez. Posesión larga y nerviosa, buscando desesperadamente una grieta en la muralla rival.",
    "👟 ¡Uy, uy, uy! Falta de entendimiento en el medio, pierden un balón tonto pero el rival no sabe aprovechar el contragolpe.",
    "👟 Minutos de máxima tensión. Nadie quiere arriesgar el balón. Mucho juego horizontal en la zona de creación.",
    "👟 El ritmo se vuelve loco. Un correcalles, de área a área, pero las defensas están achicando agua como pueden.",
    "👟 Balonazo largo en profundidad intentando buscar la espalda de la defensa, pero se marcha por línea de fondo. Demasiada fuerza.",
    "👟 Mucho juego subterráneo en el medio campo. El partido se ha vuelto táctico, muy trabado y con muchas interrupciones.",
    "👟 Presión asfixiante muy arriba. El equipo no deja respirar la salida de balón rival, obligando a pelotazos constantes.",
    "👟 ¡Tiki-taka de manual! El equipo toca y toca buscando desorganizar a la defensa, pero el rival se mantiene rocoso.",
    "👟 Posesión abrumadora pero sin profundidad. Mucho toque intrascendente en la zona de tres cuartos.",
    "👟 ¡Qué ritmo frenético! Ninguno de los dos equipos se toma un respiro, transiciones rapidísimas pero sin acierto final.",
    "👟 Partido dormido en estos momentos. Los jugadores piden agua, parece que el desgaste físico empieza a pasar factura.",
    "👟 El campo parece inclinado hacia una portería. Asedio total del equipo atacante que embotella a su rival en su área.",
    "👟 Saque de banda largo, forcejeos en el centro del campo, balones aéreos divididos... Puro fútbol británico en estos minutos."
  ]
};

// Actualización del mercado a las 00:00 
app.get('/api/cron/medianoche', async (req, res) => {
  
  // Protección para que solo Vercel pueda ejecutar esto leyendo el CRON_SECRET
  const authHeader = req.headers.authorization;
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    console.error("Intento fallido de Cron. Token recibido:", authHeader);
    return res.status(401).json({ error: 'No autorizado' });
  }

  try {
    console.log("Iniciando actualización nocturna del mercado...");
    await db.query('BEGIN');

    // Buscamos todas las ligas activas
    const ligasRes = await db.query('SELECT id_liga FROM ligas');
    
    for (const liga of ligasRes.rows) {
      const id_liga = liga.id_liga;
      console.log(`Resolviendo pujas para la liga ${id_liga}...`);

      // Obtener todos los jugadores del mercado actual de esta liga
      const jugadoresEnMercado = await db.query('SELECT id_futbolista FROM mercado_liga WHERE id_liga = $1', [id_liga]);

      // Resolver quién se lleva a cada jugador
      for (const j of jugadoresEnMercado.rows) {
        const idFutbolista = j.id_futbolista;

        // Buscar la puja más alta
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
            // Restar dinero
            await db.query('UPDATE users_liga SET dinero = dinero - $1 WHERE id_user = $2 AND id_liga = $3', [montoPujado, idGanador, id_liga]);
            // Dar jugador
            await db.query('INSERT INTO futbolista_user_liga (id_user, id_liga, id_futbolista) VALUES ($1, $2, $3)', [idGanador, id_liga, idFutbolista]);
            // Guardar en Historial
            await db.query(`
              INSERT INTO historial_transferencias (id_liga, id_futbolista, id_vendedor, id_comprador, monto, fecha, tipo)
              VALUES ($1, $2, NULL, $3, $4, NOW(), 'compra_mercado')
            `, [id_liga, idFutbolista, idGanador, montoPujado]);
          }
        }
      }

      // Sistema de compra de sistema de jugador en venta
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

      // Limpiar el mercado viejo y las pujas de ayer de ESTA liga
      await db.query('DELETE FROM pujas WHERE id_liga = $1', [id_liga]);
      await db.query('DELETE FROM mercado_liga WHERE id_liga = $1', [id_liga]);

      // Generar los 20 nuevos jugadores asegurando 3 de cada posición
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

// Simulación de partidos
app.get('/api/cron/simular-partidos', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) return res.status(401).json({ error: 'No autorizado' });

  const narrar = (arrayFrases, vars) => {
    let frase = arrayFrases[Math.floor(Math.random() * arrayFrases.length)];
    for (const key in vars) {
      frase = frase.replace(new RegExp(`{${key}}`, 'g'), vars[key]);
    }
    return frase;
  };

  try {
    const partidosRes = await db.query(`SELECT * FROM partidos WHERE estado = 'pendiente' AND fecha_partido <= NOW()`);
    if (partidosRes.rows.length === 0) return res.json({ message: 'No hay partidos pendientes.' });

    await db.query(`UPDATE futbolistas SET partidos_sancion = GREATEST(0, partidos_sancion - 1), partidos_lesion = GREATEST(0, partidos_lesion - 1)`);

    for (const partido of partidosRes.rows) {

      try {
        const bloquear = await debeBloquearJornada(
          Number(partido.id_liga),
          Number(partido.jornada)
        );

        if (bloquear) {
          const resultadoBloqueo = await bloquearAlineacionesJornada(
            Number(partido.id_liga),
            Number(partido.jornada)
          );

          console.log(
            `Jornada ${partido.jornada} de liga ${partido.id_liga} bloqueada automáticamente`,
            resultadoBloqueo
          );
        }
      } catch (err) {
        console.error(
          `Error bloqueando alineaciones de jornada ${partido.jornada} liga ${partido.id_liga}:`,
          err
        );

        // De momento NO paramos la simulación por esto.
        // Más adelante podemos hacerlo obligatorio.
      }

      await aplicarPenalizacionesHuecosVaciosJornada(
        Number(partido.id_liga),
        Number(partido.jornada),
        Number(partido.id_partido)
      );
      
      await db.query('BEGIN');
      
      // La IA solo convoca a las cartas 'normales'. Así no hay clones en el campo.
      const jugRes = await db.query(`SELECT * FROM futbolistas WHERE equipo IN ($1, $2) AND partidos_lesion = 0 AND partidos_sancion = 0 AND tipo_carta = 'normal'`, [partido.equipo_local, partido.equipo_visitante]);

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

      const alineacionGuardada = {
        local: { equipo: local.nombre, titulares: local.titulares.map(t=>t.id_futbolista), banquillo: local.banquillo.map(b=>b.id_futbolista) },
        visitante: { equipo: visit.nombre, titulares: visit.titulares.map(t=>t.id_futbolista), banquillo: visit.banquillo.map(b=>b.id_futbolista) }
      };

      [...local.titulares, ...local.banquillo, ...visit.titulares, ...visit.banquillo].forEach(j => {
        statsPartido[j.id_futbolista] = { ...j, jugo: false, goles: 0, asistencias: 0, amarillas: 0, rojas: 0, nota_final: null };
      });
      local.titulares.forEach(j => statsPartido[j.id_futbolista].jugo = true);
      visit.titulares.forEach(j => statsPartido[j.id_futbolista].jugo = true);

      // --- EL PARTIDO (70 MINS) ---
      for (let minuto = 1; minuto <= 70; minuto++) {
        if (partidoSuspendido) break;

        // DESCANSO
        if (minuto > 30 && minuto <= 40) {
          if (minuto === 31) {
            eventos.push({ minuto: 30, tipo_evento: 'info', id_futbolista: null, descripcion: '⏱️ Pita el árbitro. Jugadores al túnel de vestuarios para el descanso.' });
            [local, visit].forEach(equipo => {
              if (equipo.banquillo.length > 0 && equipo.cambiosHechos < 5 && Math.random() > 0.2) {
                const sale = equipo.titulares[Math.floor(Math.random() * equipo.titulares.length)];
                const entra = equipo.banquillo.shift();
                equipo.titulares = equipo.titulares.filter(j => j.id_futbolista !== sale.id_futbolista);
                equipo.titulares.push(entra);
                statsPartido[entra.id_futbolista].jugo = true;
                equipo.cambiosHechos++;
                eventos.push({ minuto: 30, tipo_evento: 'cambio', id_futbolista: entra.id_futbolista, descripcion: `🔄 Cambio táctico al descanso: Entra ${entra.nombre}, sale ${sale.nombre}.` });
              }
            });
          }
          if (minuto === 40) {
            eventos.push({ minuto: 31, tipo_evento: 'info', id_futbolista: null, descripcion: '⚽ Rueda de nuevo el esférico. ¡Arranca la segunda mitad!' });
          }
          continue; 
        }

        const minReal = minuto > 40 ? minuto - 10 : minuto;
        let eventoImportanteOcurrido = false;

        // GOLES
        if (Math.random() < 0.06) {
          const atacaLocal = Math.random() < 0.5;
          const atacante = atacaLocal ? local : visit;
          if (atacante.titulares.length > 0) {
            const goleador = atacante.titulares[Math.floor(Math.random() * atacante.titulares.length)];
            let asistente = null;
            let fraseGol = '';
            
            if (Math.random() < 0.5 && atacante.titulares.length > 1) {
              asistente = atacante.titulares.filter(j => j.id_futbolista !== goleador.id_futbolista)[0];
              statsPartido[asistente.id_futbolista].asistencias++;
              fraseGol = narrar(FRASES.golesAsistencia, { goleador: goleador.nombre, asistente: asistente.nombre });
            } else {
              fraseGol = narrar(FRASES.golesSolo, { goleador: goleador.nombre });
            }
            
            statsPartido[goleador.id_futbolista].goles++;
            if (atacaLocal) golesLocal++; else golesVisit++;
            eventos.push({ minuto: minReal, tipo_evento: 'gol', id_futbolista: goleador.id_futbolista, descripcion: fraseGol });
            eventoImportanteOcurrido = true;
          }
        }

        // LESIONES
        if (!eventoImportanteOcurrido && Math.random() < 0.01) {
          const sufreLesion = Math.random() < 0.5 ? local : visit;
          if (sufreLesion.titulares.length > 0) {
            const lesionado = sufreLesion.titulares[Math.floor(Math.random() * sufreLesion.titulares.length)];
            sufreLesion.titulares = sufreLesion.titulares.filter(j => j.id_futbolista !== lesionado.id_futbolista);
            const tirada = Math.random();
            let dias = 1, tipo = 'Sobrecarga muscular';
            if (tirada > 0.9) { dias = 14; tipo = 'Rotura de ligamentos'; } else if (tirada > 0.7) { dias = 7; tipo = 'Rotura fibrilar'; } else if (tirada > 0.4) { dias = 3; tipo = 'Esguince de tobillo'; }
            
            statsPartido[lesionado.id_futbolista].lesion_sufrida = { dias, tipo };
            let desc = narrar(FRASES.lesiones, { jugador: lesionado.nombre, lesion: tipo });
            
            if (sufreLesion.banquillo.length > 0) {
              const entra = sufreLesion.banquillo.shift();
              sufreLesion.titulares.push(entra);
              statsPartido[entra.id_futbolista].jugo = true;
              desc += ` Su lugar lo ocupa urgentemente ${entra.nombre}.`;
            } else { desc += ` ¡Qué drama, se quedan con 10 hombres!`; }
            
            eventos.push({ minuto: minReal, tipo_evento: 'lesion', id_futbolista: lesionado.id_futbolista, descripcion: desc });
            eventoImportanteOcurrido = true;
          }
        }

        // TARJETAS
        if (!eventoImportanteOcurrido && Math.random() < 0.04) {
          const equipoFalta = Math.random() < 0.5 ? local : visit;
          if (equipoFalta.titulares.length > 0) {
            const infractor = equipoFalta.titulares[Math.floor(Math.random() * equipoFalta.titulares.length)];
            statsPartido[infractor.id_futbolista].amarillas++;
            
            if (statsPartido[infractor.id_futbolista].amarillas === 2 || Math.random() < 0.1) {
              statsPartido[infractor.id_futbolista].rojas = 1;
              equipoFalta.titulares = equipoFalta.titulares.filter(j => j.id_futbolista !== infractor.id_futbolista);
              equipoFalta.rojas++;
              eventos.push({ minuto: minReal, tipo_evento: 'roja', id_futbolista: infractor.id_futbolista, descripcion: narrar(FRASES.rojas, { jugador: infractor.nombre }) });
              
              if (equipoFalta.rojas >= 3) {
                partidoSuspendido = true;
                if (equipoFalta === local) { golesLocal = 0; golesVisit = 3; } else { golesLocal = 3; golesVisit = 0; }
                eventos.push({ minuto: minReal, tipo_evento: 'info', descripcion: `⚖️ FORFAIT. El árbitro suspende el partido. El equipo no tiene el mínimo de jugadores tras tantas expulsiones. Derrota automática 3-0.` });
              }
            } else {
              eventos.push({ minuto: minReal, tipo_evento: 'amarilla', id_futbolista: infractor.id_futbolista, descripcion: narrar(FRASES.amarillas, { jugador: infractor.nombre }) });
            }
            eventoImportanteOcurrido = true;
          }
        }

        // NARRACIÓN DE RELLENO
        if (!eventoImportanteOcurrido && Math.random() < 0.15) {
          const atacaLocal = Math.random() < 0.5;
          const equipoAtacante = atacaLocal ? local : visit;
          const equipoDefensor = atacaLocal ? visit : local;

          if (equipoAtacante.titulares.length > 0 && equipoDefensor.titulares.length > 0) {
            const jugAtacante = equipoAtacante.titulares[Math.floor(Math.random() * equipoAtacante.titulares.length)].nombre;
            const jugDefensor = equipoDefensor.titulares[Math.floor(Math.random() * equipoDefensor.titulares.length)].nombre;
            
            const tipoRelleno = Math.random();
            let fraseInfo = '';

            if (tipoRelleno < 0.2) fraseInfo = narrar(FRASES.rellenoParadas, { atacante: jugAtacante });
            else if (tipoRelleno < 0.4) fraseInfo = narrar(FRASES.rellenoPalos, { atacante: jugAtacante });
            else if (tipoRelleno < 0.6) fraseInfo = narrar(FRASES.rellenoRegates, { atacante: jugAtacante });
            else if (tipoRelleno < 0.8) fraseInfo = narrar(FRASES.rellenoDefensas, { defensor: jugDefensor });
            else fraseInfo = narrar(FRASES.rellenoTransicion, {});

            eventos.push({ minuto: minReal, tipo_evento: 'info', id_futbolista: null, descripcion: fraseInfo });
          }
        }

        // La IA piensa en hacer cambios entre el minuto 35 y 55 reales (min 45 a 65 del bucle)
        if (!eventoImportanteOcurrido && minuto > 45 && minuto < 65 && Math.random() < 0.10) {
          
          [local, visit].forEach(equipo => {
            if (equipo.banquillo.length > 0 && equipo.cambiosHechos < 5) {
              
              const isLocal = equipo === local;
              const golesEquipo = isLocal ? golesLocal : golesVisit;
              const golesRival = isLocal ? golesVisit : golesLocal;
              const perdiendo = golesEquipo < golesRival;

              // Analizamos a los titulares en el campo
              let candidatoSalir = null;
              let motivoCambio = 'normal';

              // Si van perdiendo, buscan quitar a alguien al azar para buscar la remontada
              if (perdiendo && Math.random() < 0.6) {
                candidatoSalir = equipo.titulares[Math.floor(Math.random() * equipo.titulares.length)];
                motivoCambio = 'ofensivo';
              } 
              // Si no van perdiendo, miran si hay alguien amonestado
              else {
                const amonestados = equipo.titulares.filter(j => statsPartido[j.id_futbolista].amarillas > 0);
                if (amonestados.length > 0 && Math.random() < 0.5) {
                  candidatoSalir = amonestados[Math.floor(Math.random() * amonestados.length)];
                  motivoCambio = 'castigo';
                } 
                // Cambio normal de refresco
                else if (Math.random() < 0.3) {
                  candidatoSalir = equipo.titulares[Math.floor(Math.random() * equipo.titulares.length)];
                  motivoCambio = 'normal';
                }
              }

              // Si la IA ha decidido hacer el cambio
              if (candidatoSalir) {
                const entra = equipo.banquillo.shift();
                
                equipo.titulares = equipo.titulares.filter(j => j.id_futbolista !== candidatoSalir.id_futbolista);
                equipo.titulares.push(entra);
                
                statsPartido[entra.id_futbolista].jugo = true;
                equipo.cambiosHechos++;

                let diccionarioFrases = FRASES.cambios;
                if (motivoCambio === 'ofensivo') diccionarioFrases = FRASES.cambiosOfensivos;
                if (motivoCambio === 'castigo') diccionarioFrases = FRASES.cambiosCastigo;

                const fraseCambio = narrar(diccionarioFrases, { entra: entra.nombre, sale: candidatoSalir.nombre });

                eventos.push({ 
                  minuto: minReal, 
                  tipo_evento: 'cambio', 
                  id_futbolista: entra.id_futbolista, 
                  descripcion: fraseCambio 
                });
                
                eventoImportanteOcurrido = true;
              }
            }
          });
        }
      }

      // --- POST-PARTIDO: Notas, Puntos y BD ---
      for (let id in statsPartido) {
        let st = statsPartido[id];
        if (!st.jugo) continue;
        let nota = (Math.random() * 5.0) + 2.0; 
        nota += (st.goles * 2.0) + (st.asistencias * 1.5);
        if (st.rojas > 0) nota = 1.0; else if (st.amarillas > 0) nota -= 1.0;
        if (st.equipo === partido.equipo_local && golesVisit === 0 && (st.posicion === 'DF' || st.posicion === 'PT')) nota += 1.5;
        if (st.equipo === partido.equipo_visitante && golesLocal === 0 && (st.posicion === 'DF' || st.posicion === 'PT')) nota += 1.5;
        st.nota_final = Math.max(0, Math.min(10, nota)).toFixed(1);

        // Aplicamos lesiones, rojas y forma a todos los que tengan ese nombre (Normales, Especiales, Ultras)
        if (st.lesion_sufrida) await db.query(`UPDATE futbolistas SET estado_lesion = $1, partidos_lesion = $2 WHERE nombre = $3`, [st.lesion_sufrida.tipo, st.lesion_sufrida.dias, st.nombre]);
        if (st.rojas > 0) await db.query(`UPDATE futbolistas SET partidos_sancion = $1 WHERE nombre = $2`, [Math.floor(Math.random() * 4) + 1, st.nombre]);
        
        await db.query(`UPDATE futbolistas SET forma_actual = $1 WHERE nombre = $2`, [st.nota_final, st.nombre]);

        // La fluctuación de media y precio solo afecta a las normales
        if (st.tipo_carta !== 'ultra') {
          let nuevaMedia = st.media;
          if (st.nota_final > 7.5 && Math.random() < ((100 - st.media) / 100)) nuevaMedia = Math.min(94, nuevaMedia + 1);
          if (st.nota_final < 4.0 && Math.random() < 0.3) nuevaMedia = Math.max(60, nuevaMedia - 1);
          
          //Redondeo
          let precioBase = Math.min(50000000, Math.max(1000000, Math.floor(Math.pow(1.15, nuevaMedia - 60) * 1000000)));
          let nuevoPrecio = Math.round(precioBase / 100000) * 100000;

          await db.query(`UPDATE futbolistas SET media = $1, precio = $2 WHERE id_futbolista = $3`, [nuevaMedia, nuevoPrecio, st.id_futbolista]);
        }
      }

      await db.query(`UPDATE partidos SET goles_local = $1, goles_visitante = $2, estado = 'finalizado', alineaciones = $4 WHERE id_partido = $3`, [golesLocal, golesVisit, partido.id_partido, JSON.stringify(alineacionGuardada)]);
      for (const ev of eventos) {
        await db.query(`INSERT INTO eventos_partido (id_partido, minuto, tipo_evento, id_futbolista, id_asistente, descripcion) VALUES ($1, $2, $3, $4, $5, $6)`, [partido.id_partido, ev.minuto, ev.tipo_evento, ev.id_futbolista, ev.id_asistente, ev.descripcion]);
      }

      // --- PUNTOS + HABILIDADES DESDE ALINEACIÓN BLOQUEADA ---
      const mánagers = await db.query(
        `SELECT DISTINCT id_user FROM users_liga WHERE id_liga = $1`,
        [partido.id_liga]
      );

      for (const man of mánagers.rows) {
        const alineacionRes = await db.query(`
          SELECT
            aj.id_liga,
            aj.jornada,
            aj.id_user,
            aj.id_futbolista,
            aj.hueco_plantilla,
            aj.es_hueco_vacio,
            aj.tipo_carta_snapshot,
            aj.nombre_snapshot AS nombre,
            aj.posicion_snapshot AS posicion,
            aj.media_snapshot AS media,
            aj.codigo_habilidad_snapshot AS codigo_habilidad
          FROM alineaciones_jornada aj
          WHERE aj.id_liga = $1
            AND aj.jornada = $2
            AND aj.id_user = $3
          ORDER BY 
            CASE 
              WHEN aj.hueco_plantilla = 'hueco-12' THEN 12
              ELSE CAST(REPLACE(aj.hueco_plantilla, 'hueco-', '') AS integer)
            END ASC
        `, [partido.id_liga, partido.jornada, man.id_user]);

        let suPlantilla = alineacionRes.rows;

        // Seguridad: si por algún motivo la jornada no estaba bloqueada, la bloqueamos y recargamos.
        if (suPlantilla.length === 0) {
          await bloquearAlineacionesJornada(Number(partido.id_liga), Number(partido.jornada));

          const recarga = await db.query(`
            SELECT
              aj.id_liga,
              aj.jornada,
              aj.id_user,
              aj.id_futbolista,
              aj.hueco_plantilla,
              aj.es_hueco_vacio,
              aj.tipo_carta_snapshot,
              aj.nombre_snapshot AS nombre,
              aj.posicion_snapshot AS posicion,
              aj.media_snapshot AS media,
              aj.codigo_habilidad_snapshot AS codigo_habilidad
            FROM alineaciones_jornada aj
            WHERE aj.id_liga = $1
              AND aj.jornada = $2
              AND aj.id_user = $3
            ORDER BY 
              CASE 
                WHEN aj.hueco_plantilla = 'hueco-12' THEN 12
                ELSE CAST(REPLACE(aj.hueco_plantilla, 'hueco-', '') AS integer)
              END ASC
          `, [partido.id_liga, partido.jornada, man.id_user]);

          suPlantilla = recarga.rows;
        }

        let puntosTotalesManager = 0;

        const jugador12 = suPlantilla.find(j => j.hueco_plantilla === 'hueco-12' && !j.es_hueco_vacio);
        const ultraCode = jugador12 ? jugador12.codigo_habilidad : null;

        const jugadoresPuntuables = suPlantilla.filter(j => j.hueco_plantilla !== 'hueco-12');

        const espejismoActivo =
          jugadoresPuntuables.some(j => j.codigo_habilidad === 'HabEspecial_Espejismo' && !j.es_hueco_vacio) &&
          (Math.random() < 0.10);

        const bonusLider = jugadoresPuntuables.filter(
          j => j.codigo_habilidad === 'HabEspecial_LiderEspiritual' && !j.es_hueco_vacio
        ).length;

        let primeraRojaPerdonada = false;

        for (const mio of jugadoresPuntuables) {
          // Penalización por hueco vacío. Hueco-12 ya está excluido.
          if (mio.es_hueco_vacio) {
            continue;
          }

          // Buscamos las estadísticas del partido por nombre.
          // Esto mantiene la compatibilidad con cartas especiales que comparten nombre con su carta base.
          const stArray = Object.values(statsPartido);
          const st = stArray.find(s => s.nombre === mio.nombre);

          if (st && st.jugo) {
            const hab = mio.codigo_habilidad;
            let misPuntos = Math.round(parseFloat(st.nota_final));
            let multGoles = hab === 'HabEspecial_Francotirador' ? 10 : 5;

            if (st.rojas > 0) {
              if (ultraCode === 'HabUltra_Wade' && !primeraRojaPerdonada) {
                primeraRojaPerdonada = true;
              } else if (hab !== 'HabEspecial_JuegoCaballeros') {
                misPuntos -= 5;
              }
            } else if (st.amarillas > 0 && hab !== 'HabEspecial_JuegoCaballeros') {
              misPuntos -= 2;
            }

            misPuntos += (st.goles * multGoles) + (st.asistencias * 3);

            const isLocal = st.equipo === partido.equipo_local;
            const golesEquipo = isLocal ? golesLocal : golesVisit;
            const golesRival = isLocal ? golesVisit : golesLocal;
            const win = golesEquipo > golesRival;
            const loss = golesEquipo < golesRival;

            if (hab === 'HabEspecial_Egoista' && st.goles > 0 && st.goles === golesEquipo) misPuntos += 10;
            if (hab === 'HabEspecial_EfectoBolaNieve') misPuntos += golesEquipo;

            if (
              hab === 'HabEspecial_HeroeAgonico' &&
              win &&
              eventos.some(e => e.id_futbolista === st.id_futbolista && e.minuto >= 50 && e.tipo_evento === 'gol')
            ) {
              misPuntos += 8;
            }

            if (hab === 'HabEspecial_CerrojoAbsoluto' && golesRival === 0) misPuntos = Math.round(misPuntos * 1.5);
            if (hab === 'HabEspecial_SalvadorAlambre' && win && (golesEquipo - golesRival === 1)) misPuntos += 7;
            if (hab === 'HabEspecial_TodoONada') misPuntos = win ? misPuntos * 2 : 0;
            if (hab === 'HabEspecial_DadoDelCaos') misPuntos += (Math.random() > 0.5 ? 10 : -5);
            if (hab === 'HabEspecial_ImanFaltas') misPuntos += Math.floor(Math.random() * 5) + 1;
            if (hab === 'HabEspecial_Trotamundos' && !isLocal) misPuntos += 3;
            if (hab === 'HabEspecial_AnclaLocal' && isLocal) misPuntos += 4;
            if (hab === 'HabEspecial_OrgulloCaido' && loss && (golesRival - golesEquipo >= 3) && misPuntos < 2) misPuntos = 2;

            misPuntos += bonusLider;
            if (espejismoActivo) misPuntos *= 2;

            if (ultraCode === 'HabUltra_Trebolin' && (st.posicion === 'DF' || st.posicion === 'PT')) misPuntos = Math.round(misPuntos * 1.20);
            if (ultraCode === 'HabUltra_Wade') misPuntos = Math.round(misPuntos * 1.10);
            if (ultraCode === 'HabUltra_Cuestarriba' && (st.posicion === 'DF' || st.posicion === 'MC')) misPuntos += 3;
            if (ultraCode === 'HabUltra_Evil' && st.posicion === 'DL') {
              const golesLocalHT = eventos.filter(e => e.tipo_evento === 'gol' && e.minuto <= 30 && local.titulares.some(j => j.id_futbolista === e.id_futbolista)).length;
              const golesVisitHT = eventos.filter(e => e.tipo_evento === 'gol' && e.minuto <= 30 && visit.titulares.some(j => j.id_futbolista === e.id_futbolista)).length;
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

            await db.query(`
              INSERT INTO rendimiento_partido
              (id_partido, id_futbolista, id_user, nota_base, puntos_totales, goles, asistencias, amarillas, rojas)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            `, [
              partido.id_partido,
              mio.id_futbolista,
              man.id_user,
              st.nota_final,
              misPuntos,
              st.goles,
              st.asistencias,
              st.amarillas,
              st.rojas
            ]);

            puntosTotalesManager += misPuntos;
          }
        }

      }
      await db.query('COMMIT');
    }
    res.json({ message: 'Simulación completada con Multiverso corregido.' });
  } catch (err) {
    await db.query('ROLLBACK');
    console.error("Error Simulación:", err);
    res.status(500).json({ error: 'Fallo brutal en el motor' });
  }
});

// Reparto de premios por jornada
app.get('/api/cron/premios-jornada', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) return res.status(401).json({ error: 'No autorizado' });

  try {
    await db.query('BEGIN');
    
    // Buscamos jornadas donde todos los partidos estén finalizados y no se hayan pagado aún
    const jornadasPagar = await db.query(`
      SELECT id_liga, jornada
      FROM partidos
      GROUP BY id_liga, jornada
      HAVING 
        bool_and(
          estado = 'finalizado'
          AND fecha_partido + interval '70 minutes' <= NOW()
        )
        AND bool_and(premios_pagados = false)
    `);

    if (jornadasPagar.rows.length === 0) {
      await db.query('ROLLBACK');
      return res.json({ message: 'No hay jornadas pendientes de pago.' });
    }

    for (const j of jornadasPagar.rows) {
      const { id_liga, jornada } = j;
      
      // Obtener el ranking exacto de esa jornada
      const ranking = await db.query(`
        SELECT 
          ul.id_user,
          u.username,
          COALESCE(SUM(
            CASE 
              WHEN p.id_partido IS NOT NULL THEN rp.puntos_totales 
              ELSE 0 
            END
          ), 0) as puntos_jornada
        FROM users_liga ul
        JOIN users u ON ul.id_user = u.id
        LEFT JOIN rendimiento_partido rp 
          ON rp.id_user = ul.id_user
        LEFT JOIN partidos p 
          ON rp.id_partido = p.id_partido
          AND p.id_liga = ul.id_liga
          AND p.jornada = $2
          AND p.estado = 'finalizado'
          AND p.fecha_partido + interval '70 minutes' <= NOW()
        WHERE ul.id_liga = $1
        GROUP BY ul.id_user, u.username
        ORDER BY puntos_jornada DESC
      `, [id_liga, jornada]);

      let mensajeChat = `🏆 ¡PREMIOS DE LA JORNADA ${jornada} REPARTIDOS! 🏆\n\n`;

      // Repartir los maletines de dinero
      for (let i = 0; i < ranking.rows.length; i++) {
        const manager = ranking.rows[i];
        const puntos = Number(manager.puntos_jornada);
        
        const bonusPorPuesto = [
          5000000,
          3500000,
          2500000,
          1500000,
          1000000,
          750000,
          500000,
          300000,
          150000,
          0
        ];

        let premio = 0;

        if (puntos > 0) {
          premio += puntos * 100000;
        }

        if (puntos >= 0) {
          premio += bonusPorPuesto[i] || 0;
        }

        if (premio > 0) {
          // Ingresar dinero
          await db.query('UPDATE users_liga SET dinero = dinero + $1 WHERE id_user = $2 AND id_liga = $3', [premio, manager.id_user, id_liga]);
          
          // Construir el mensaje del podio para el chat
          if (premio > 0 && puntos >= 0) {
            const posicion = `${i + 1}º`;
            mensajeChat += `${posicion} ${manager.username}: ${puntos} pts (+${new Intl.NumberFormat('es-ES').format(premio)} Tc)\n`;
          }
        }
      }

      // Marcar la jornada entera como pagada para no repetir el pago mañana
      await db.query('UPDATE partidos SET premios_pagados = true WHERE id_liga = $1 AND jornada = $2', [id_liga, jornada]);

      // El Owner hace el anuncio oficial en el Chat General
      await db.query(`
        INSERT INTO chat_general (id_liga, id_user, mensaje) 
        VALUES ($1, (SELECT id_user FROM users_liga WHERE id_liga = $1 AND rol = 'owner' LIMIT 1), $2)
      `, [id_liga, mensajeChat]);
    }

    await db.query('COMMIT');
    res.json({ message: 'Premios repartidos con éxito y anunciados en el chat.' });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error("Error en reparto de premios:", err);
    res.status(500).json({ error: 'Fallo al repartir los premios' });
  }
});

router.post('/:id_liga/reparar-penalizaciones-antiguas', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
  const { id_liga } = req.params;

  try {
    await db.query('BEGIN');

    const jornadasRes = await db.query(`
      SELECT DISTINCT jornada
      FROM partidos
      WHERE id_liga = $1
        AND fecha_partido <= NOW()
      ORDER BY jornada ASC
    `, [id_liga]);

    const huecosObligatorios = [
      'hueco-1',
      'hueco-2',
      'hueco-3',
      'hueco-4',
      'hueco-5',
      'hueco-6',
      'hueco-7',
      'hueco-8',
      'hueco-9',
      'hueco-10',
      'hueco-11'
    ];

    let jornadasProcesadas = 0;
    let penalizacionesInsertadas = 0;

    for (const j of jornadasRes.rows) {
      const jornada = j.jornada;

      const usuariosRes = await db.query(`
        SELECT id_user
        FROM users_liga
        WHERE id_liga = $1
      `, [id_liga]);

      const partidoReferenciaRes = await db.query(`
        SELECT id_partido
        FROM partidos
        WHERE id_liga = $1
          AND jornada = $2
        ORDER BY fecha_partido ASC
        LIMIT 1
      `, [id_liga, jornada]);

      if (partidoReferenciaRes.rows.length === 0) {
        continue;
      }

      const idPartidoReferencia = partidoReferenciaRes.rows[0].id_partido;

      for (const usuario of usuariosRes.rows) {
        const idUser = usuario.id_user;

        const alineacionExiste = await db.query(`
          SELECT 1
          FROM alineaciones_jornada
          WHERE id_liga = $1
            AND jornada = $2
            AND id_user = $3
          LIMIT 1
        `, [id_liga, jornada, idUser]);

        if (alineacionExiste.rows.length === 0) {
          for (const hueco of huecosObligatorios) {
            await db.query(`
              INSERT INTO alineaciones_jornada (
                id_liga,
                jornada,
                id_user,
                id_futbolista,
                hueco_plantilla,
                es_hueco_vacio
              )
              VALUES ($1, $2, $3, NULL, $4, true)
              ON CONFLICT (id_liga, jornada, id_user, hueco_plantilla) DO NOTHING
            `, [id_liga, jornada, idUser, hueco]);
          }
        }

        const yaPenalizado = await db.query(`
          SELECT 1
          FROM rendimiento_partido rp
          JOIN partidos p ON p.id_partido = rp.id_partido
          WHERE p.id_liga = $1
            AND p.jornada = $2
            AND rp.id_user = $3
            AND rp.tipo_registro = 'hueco_vacio'
          LIMIT 1
        `, [id_liga, jornada, idUser]);

        if (yaPenalizado.rows.length > 0) {
          continue;
        }

        const huecosVaciosRes = await db.query(`
          SELECT hueco_plantilla
          FROM alineaciones_jornada
          WHERE id_liga = $1
            AND jornada = $2
            AND id_user = $3
            AND es_hueco_vacio = true
            AND hueco_plantilla != 'hueco-12'
        `, [id_liga, jornada, idUser]);

        for (const hueco of huecosVaciosRes.rows) {
          await db.query(`
            INSERT INTO rendimiento_partido (
              id_partido,
              id_futbolista,
              id_user,
              nota_base,
              puntos_totales,
              goles,
              asistencias,
              amarillas,
              rojas,
              tipo_registro,
              hueco_plantilla
            )
            VALUES ($1, NULL, $2, NULL, -3, 0, 0, 0, 0, 'hueco_vacio', $3)
          `, [
            idPartidoReferencia,
            idUser,
            hueco.hueco_plantilla
          ]);

          penalizacionesInsertadas++;
        }
      }

      jornadasProcesadas++;
    }

    await db.query('COMMIT');

    res.json({
      message: 'Penalizaciones antiguas reparadas',
      jornadas_procesadas: jornadasProcesadas,
      penalizaciones_insertadas: penalizacionesInsertadas
    });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error('Error reparando penalizaciones antiguas:', err);
    res.status(500).json({ message: 'Error reparando penalizaciones antiguas' });
  }
});

app.use('/api/ligas', router);
app.use('/api/mercado', mercadoRouter);

// Export para Vercel
module.exports = app;