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
  const { nombre, clave, max_jugadores } = req.body;
  const idUser = req.user.id;

  if (!nombre || !clave || !max_jugadores) return res.status(400).json({ message: 'Todos los campos son obligatorios' });

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
      [idUser, idLiga, 'owner', 100000000, 0]
    );

    // Actualizar el número de jugadores a 1
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

// Ascender un usuario a admin (solo owner)
router.put('/:id_liga/make-admin/:id_user', verifyToken, requireLeagueRole(['owner']), async (req, res) => {
  const { id_liga, id_user } = req.params;
  try {
    await db.query('UPDATE users_liga SET rol=$1 WHERE id_user=$2 AND id_liga=$3', ['admin', id_user, id_liga]);
    res.json({ message: 'Usuario ascendido a admin' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al ascender a admin' });
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
        -- Subconsulta: Suma de todas mis pujas activas en esta liga
        (SELECT COALESCE(SUM(monto), 0) FROM pujas 
         WHERE id_user = $1 AND id_liga = $2) as total_pujado,
         
        -- Subconsulta: Suma de precios de mis jugadores en venta
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
        u.id, 
        u.username, 
        u.avatar, 
        ul.puntos, 
        ul.rol,
        (SELECT COUNT(*) FROM futbolista_user_liga ful 
         WHERE ful.id_user = u.id AND ful.id_liga = $1) as total_jugadores
      FROM users_liga ul
      JOIN users u ON u.id = ul.id_user
      WHERE ul.id_liga = $1
      ORDER BY ul.puntos DESC
    `, [id_liga]);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error obteniendo clasificación' });
  }
});

router.get('/:id_liga/mis-jugadores', verifyToken, async (req, res) => {
  const { id_liga } = req.params;
  const idUser = req.user.id;

  try {
    const result = await db.query(`
      SELECT 
        f.id_futbolista, f.nombre, f.posicion, f.precio, f.equipo, f.media,
        f.imagen, f.ataque, f.defensa, f.parada, f.pase,
        ful.en_venta, ful.precio_venta
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

// Obtener los jugadores y datos de un rival
router.get('/:id_liga/jugadores-rival/:id_usuario_rival', verifyToken, async (req, res) => {
  const { id_liga, id_usuario_rival } = req.params;

  try {
    const rivalRes = await db.query('SELECT username, avatar FROM users WHERE id = $1', [id_usuario_rival]);
    const rivalInfo = rivalRes.rows[0];

    const result = await db.query(`
      SELECT 
        f.id_futbolista, f.nombre, f.posicion, f.precio, f.equipo, f.media,
        f.imagen, f.ataque, f.defensa, f.parada, f.pase,
        ful.en_venta, ful.precio_venta
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
    `, [id_liga, id_usuario_rival]);

    res.json({
      rival: rivalInfo,
      jugadores: result.rows
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error obteniendo jugadores del rival' });
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

  try {
    // Comprobar si hay mercado y si sigue siendo válido
    const mercadoActual = await db.query(`
      SELECT fecha_generacion FROM mercado_liga WHERE id_liga = $1 LIMIT 1
    `, [id_liga]);

    let regenerar = false;

    if (mercadoActual.rows.length === 0) {
      regenerar = true;
    } else {
      const fecha = new Date(mercadoActual.rows[0].fecha_generacion);
      const ahora = new Date();
      const diffHoras = (ahora - fecha) / (1000 * 60 * 60);
      if (diffHoras >= 24) regenerar = true;
    }

    if (regenerar && mercadoActual.rows.length > 0) {
      console.log(`Regenerando mercado para liga ${id_liga}... Resolviendo pujas.`);

      // 1. Obtener todos los jugadores que estaban en el mercado
      const jugadoresEnMercado = await db.query(
        'SELECT id_futbolista FROM mercado_liga WHERE id_liga = $1',
        [id_liga]
      );

      for (const j of jugadoresEnMercado.rows) {
        const idFutbolista = j.id_futbolista;

        // 2. Buscar la puja MÁS ALTA para este jugador
        const pujaGanadora = await db.query(`
          SELECT * FROM pujas 
          WHERE id_liga = $1 AND id_futbolista = $2 
          ORDER BY monto DESC 
          LIMIT 1
        `, [id_liga, idFutbolista]);

        if (pujaGanadora.rows.length > 0) {
          const ganador = pujaGanadora.rows[0];
          const idGanador = ganador.id_user;
          const montoPujado = Number(ganador.monto);

          // 3. Verificar (otra vez por seguridad) si el ganador tiene dinero
          const saldoGanador = await db.query(
            'SELECT dinero FROM users_liga WHERE id_user = $1 AND id_liga = $2',
            [idGanador, id_liga]
          );

          if (saldoGanador.rows.length > 0 && Number(saldoGanador.rows[0].dinero) >= montoPujado) {
            // A) Restar dinero al ganador
            await db.query(
              'UPDATE users_liga SET dinero = dinero - $1 WHERE id_user = $2 AND id_liga = $3',
              [montoPujado, idGanador, id_liga]
            );

            // B) Dar jugador al ganador (Tabla futbolista_user_liga)
            await db.query(
              'INSERT INTO futbolista_user_liga (id_user, id_liga, id_futbolista) VALUES ($1, $2, $3)',
              [idGanador, id_liga, idFutbolista]
            );

            // C) Guardar en Historial
            await db.query(`
              INSERT INTO historial_transferencias 
              (id_liga, id_futbolista, id_vendedor, id_comprador, monto, fecha, tipo)
              VALUES ($1, $2, NULL, $3, $4, NOW(), 'compra_mercado')
            `, [id_liga, idFutbolista, idGanador, montoPujado]); // Vendedor NULL = Sistema

            console.log(`Jugador ${idFutbolista} vendido a usuario ${idGanador} por ${montoPujado}`);
          }
        }
      }

      // 4. Limpiar las pujas de ayer (ya procesadas o perdidas)
      await db.query('DELETE FROM pujas WHERE id_liga = $1', [id_liga]);
      
      // 5. Borrar mercado viejo
      await db.query('DELETE FROM mercado_liga WHERE id_liga = $1', [id_liga]);
    }

    if (regenerar) {
      const nuevosJugadores = await db.query(`
        WITH Disponibles AS (
          SELECT id_futbolista, posicion,
                 ROW_NUMBER() OVER(PARTITION BY posicion ORDER BY RANDOM()) as rn,
                 RANDOM() as rnd
          FROM futbolistas 
          WHERE id_futbolista NOT IN (
            SELECT id_futbolista FROM futbolista_user_liga WHERE id_liga = $1
          )
        )
        SELECT id_futbolista FROM Disponibles 
        ORDER BY 
          CASE WHEN rn <= 3 THEN 0 ELSE 1 END, 
          rnd
        LIMIT 20
      `, [id_liga]);

      for (const j of nuevosJugadores.rows) {
        await db.query(`
          INSERT INTO mercado_liga (id_liga, id_futbolista, fecha_generacion)
          VALUES ($1, $2, NOW())
        `, [id_liga, j.id_futbolista]);
      }
    }

    // Devolver mercado actual (con JOIN para escudos y media)
    const idUser = req.user.id;

    const mercado = await db.query(`
      -- PARTE 1: JUGADORES DE LA BANCA
      SELECT 
        f.id_futbolista, f.nombre, f.posicion, f.equipo, f.media, f.precio as precio, 
        NULL::int as id_vendedor, NULL::text as vendedor_name,
        CASE WHEN p.id_user IS NOT NULL THEN true ELSE false END as pujado_por_mi,
        COALESCE(p.monto, 0) as mi_puja_actual,
        -- ¡AQUÍ ESTÁ LO NUEVO!
        f.imagen, f.ataque, f.defensa, f.parada, f.pase

      FROM mercado_liga ml
      JOIN futbolistas f ON f.id_futbolista = ml.id_futbolista
      LEFT JOIN pujas p ON p.id_futbolista = f.id_futbolista AND p.id_liga = $1 AND p.id_user = $2
      WHERE ml.id_liga = $1

      UNION

      -- PARTE 2: JUGADORES DE OTROS USUARIOS
      SELECT 
        f.id_futbolista, f.nombre, f.posicion, f.equipo, f.media, ful.precio_venta as precio, 
        ful.id_user as id_vendedor, u.username as vendedor_name, false as pujado_por_mi, 0 as mi_puja_actual,
        -- ¡AQUÍ TAMBIÉN LO NUEVO!
        f.imagen, f.ataque, f.defensa, f.parada, f.pase

      FROM futbolista_user_liga ful
      JOIN futbolistas f ON f.id_futbolista = ful.id_futbolista
      JOIN users u ON u.id = ful.id_user
      WHERE ful.id_liga = $1 AND ful.en_venta = true
    `, [id_liga, idUser]);

    // Calcular fecha para el contador
    const fechaGen = mercadoActual.rows.length 
      ? mercadoActual.rows[0].fecha_generacion 
      : new Date();

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


// 1. Obtener los mensajes del Chat General de la Liga
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

// 2. Enviar un mensaje al Chat General
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

// 3. Obtener la Bandeja de Entrada (Mensajes Privados)
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

// 1. Enviar un Mensaje Normal (Desde la Clasificación)
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

// 2. Enviar una Oferta por un Jugador (Desde Plantilla Rival)
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

// 3. ACEPTAR LA OFERTA (Hace el intercambio de jugador y dinero automático)
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

// 4. Marcar mensaje como leído al abrirlo
router.put('/:id_liga/mensajes/:id_mensaje/leer', verifyToken, async (req, res) => {
  try {
    await db.query('UPDATE mensajes_privados SET leido = true WHERE id_privado = $1', [req.params.id_mensaje]);
    res.json({ message: 'Leído' });
  } catch (err) { res.status(500).json({ message: 'Error' }); }
});

// 5. Rechazar una oferta (o contraofertar si mandas texto)
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

// Export para Vercel
module.exports = app;