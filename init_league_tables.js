const db = require('./db');

async function initLeagueTables() {
  try {

    // 1. LIGAS
    await db.query(`
      CREATE TABLE IF NOT EXISTS ligas (
        id_liga INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        numero_jugadores INT NOT NULL DEFAULT 0,
        max_jugadores INT NOT NULL,
        clave VARCHAR(50) NOT NULL,

        temporada_estado VARCHAR(20) NOT NULL DEFAULT 'inactiva',
        dinero_inicial BIGINT DEFAULT 100000000,
        dar_plantilla_inicial BOOLEAN DEFAULT false,

        fecha_inicio_temporada TIMESTAMP NULL,
        fecha_fin_temporada TIMESTAMP NULL,
        reset_automatico_en TIMESTAMP NULL,

        created_at TIMESTAMP DEFAULT NOW()
      );
    `);


    // 2. USERS_LIGA
    await db.query(`
      CREATE TABLE IF NOT EXISTS users_liga (
        id_user INT NOT NULL,
        id_liga INT NOT NULL,

        dinero BIGINT DEFAULT 0,
        puntos INT DEFAULT 0,
        rol VARCHAR(20) NOT NULL DEFAULT 'user',
        formacion VARCHAR(20) DEFAULT '4-3-3',

        created_at TIMESTAMP DEFAULT NOW(),

        PRIMARY KEY (id_user, id_liga),

        FOREIGN KEY (id_user)
          REFERENCES users(id)
          ON DELETE CASCADE,

        FOREIGN KEY (id_liga)
          REFERENCES ligas(id_liga)
          ON DELETE CASCADE
      );
    `);


    // 3. FUTBOLISTAS
    await db.query(`
      CREATE TABLE IF NOT EXISTS futbolistas (
        id_futbolista INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

        nombre VARCHAR(100) NOT NULL,
        posicion VARCHAR(50) NOT NULL,
        equipo VARCHAR(100) NOT NULL,

        media INT DEFAULT 60,
        precio BIGINT NOT NULL DEFAULT 1000000,

        imagen VARCHAR(500),

        ataque INT DEFAULT 0,
        defensa INT DEFAULT 0,
        pase INT DEFAULT 0,
        parada INT DEFAULT 0,

        tipo_carta VARCHAR(30) NOT NULL DEFAULT 'normal',
        codigo_habilidad VARCHAR(100),
        descripcion TEXT,

        partidos_lesion INT DEFAULT 0,
        partidos_sancion INT DEFAULT 0,
        estado_lesion VARCHAR(100),
        forma_actual DECIMAL(3,1) DEFAULT 6.0,

        created_at TIMESTAMP DEFAULT NOW()
      );
    `);


    // 4. FUTBOLISTA_USER_LIGA
    await db.query(`
      CREATE TABLE IF NOT EXISTS futbolista_user_liga (
        id_user INT NOT NULL,
        id_liga INT NOT NULL,
        id_futbolista INT NOT NULL,

        en_venta BOOLEAN DEFAULT false,
        precio_venta BIGINT DEFAULT 0,

        es_titular BOOLEAN DEFAULT false,
        hueco_plantilla VARCHAR(30),

        created_at TIMESTAMP DEFAULT NOW(),

        PRIMARY KEY (id_user, id_liga, id_futbolista),

        FOREIGN KEY (id_user, id_liga)
          REFERENCES users_liga(id_user, id_liga)
          ON DELETE CASCADE,

        FOREIGN KEY (id_futbolista)
          REFERENCES futbolistas(id_futbolista)
          ON DELETE CASCADE
      );
    `);


    // 5. MERCADO_LIGA
    await db.query(`
      CREATE TABLE IF NOT EXISTS mercado_liga (
        id_liga INT NOT NULL,
        id_futbolista INT NOT NULL,
        fecha_generacion TIMESTAMP NOT NULL DEFAULT NOW(),

        PRIMARY KEY (id_liga, id_futbolista),

        FOREIGN KEY (id_liga)
          REFERENCES ligas(id_liga)
          ON DELETE CASCADE,

        FOREIGN KEY (id_futbolista)
          REFERENCES futbolistas(id_futbolista)
          ON DELETE CASCADE
      );
    `);


    // 6. PUJAS
    await db.query(`
      CREATE TABLE IF NOT EXISTS pujas (
        id_puja INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

        id_liga INT NOT NULL,
        id_futbolista INT NOT NULL,
        id_user INT NOT NULL,

        monto BIGINT NOT NULL,
        fecha TIMESTAMP DEFAULT NOW(),

        FOREIGN KEY (id_liga)
          REFERENCES ligas(id_liga)
          ON DELETE CASCADE,

        FOREIGN KEY (id_futbolista)
          REFERENCES futbolistas(id_futbolista)
          ON DELETE CASCADE,

        FOREIGN KEY (id_user)
          REFERENCES users(id)
          ON DELETE CASCADE
      );
    `);


    // 7. HISTORIAL_TRANSFERENCIAS
    await db.query(`
      CREATE TABLE IF NOT EXISTS historial_transferencias (
        id_historial INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

        id_liga INT NOT NULL,
        id_futbolista INT NOT NULL,

        id_vendedor INT NULL,
        id_comprador INT NULL,

        monto BIGINT NOT NULL,
        fecha TIMESTAMP DEFAULT NOW(),

        tipo VARCHAR(30) NOT NULL CHECK (
          tipo IN (
            'compra_mercado',
            'compra_usuario',
            'venta_rapida',
            'venta_sistema'
          )
        ),

        FOREIGN KEY (id_liga)
          REFERENCES ligas(id_liga)
          ON DELETE CASCADE,

        FOREIGN KEY (id_futbolista)
          REFERENCES futbolistas(id_futbolista)
          ON DELETE CASCADE,

        FOREIGN KEY (id_vendedor)
          REFERENCES users(id)
          ON DELETE SET NULL,

        FOREIGN KEY (id_comprador)
          REFERENCES users(id)
          ON DELETE SET NULL
      );
    `);


    // 8. OFERTAS_PRIVADAS
    await db.query(`
      CREATE TABLE IF NOT EXISTS ofertas_privadas (
        id_oferta INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

        id_liga INT NOT NULL,
        id_futbolista INT NOT NULL,

        id_comprador INT NOT NULL,
        id_vendedor INT NOT NULL,

        monto BIGINT NOT NULL,

        estado VARCHAR(20) DEFAULT 'pendiente' CHECK (
          estado IN (
            'pendiente',
            'aceptada',
            'rechazada',
            'caducada'
          )
        ),

        fecha_creacion TIMESTAMP DEFAULT NOW(),

        FOREIGN KEY (id_liga)
          REFERENCES ligas(id_liga)
          ON DELETE CASCADE,

        FOREIGN KEY (id_futbolista)
          REFERENCES futbolistas(id_futbolista)
          ON DELETE CASCADE,

        FOREIGN KEY (id_comprador)
          REFERENCES users(id)
          ON DELETE CASCADE,

        FOREIGN KEY (id_vendedor)
          REFERENCES users(id)
          ON DELETE CASCADE
      );
    `);


    // 9. CHAT_GENERAL
    await db.query(`
      CREATE TABLE IF NOT EXISTS chat_general (
        id_mensaje INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

        id_liga INT NOT NULL,
        id_user INT NULL,

        mensaje TEXT NOT NULL,
        fecha TIMESTAMP DEFAULT NOW(),

        FOREIGN KEY (id_liga)
          REFERENCES ligas(id_liga)
          ON DELETE CASCADE,

        FOREIGN KEY (id_user)
          REFERENCES users(id)
          ON DELETE SET NULL
      );
    `);


    // 10. MENSAJES_PRIVADOS
    await db.query(`
      CREATE TABLE IF NOT EXISTS mensajes_privados (
        id_privado INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

        id_liga INT NOT NULL,

        id_remitente INT NULL,
        id_destinatario INT NOT NULL,

        tipo VARCHAR(30) DEFAULT 'texto',
        asunto VARCHAR(150),
        contenido TEXT NOT NULL,

        leido BOOLEAN DEFAULT false,

        id_oferta INT NULL,

        fecha TIMESTAMP DEFAULT NOW(),

        FOREIGN KEY (id_liga)
          REFERENCES ligas(id_liga)
          ON DELETE CASCADE,

        FOREIGN KEY (id_remitente)
          REFERENCES users(id)
          ON DELETE SET NULL,

        FOREIGN KEY (id_destinatario)
          REFERENCES users(id)
          ON DELETE CASCADE,

        FOREIGN KEY (id_oferta)
          REFERENCES ofertas_privadas(id_oferta)
          ON DELETE SET NULL
      );
    `);


    // 11. PARTIDOS
    await db.query(`
      CREATE TABLE IF NOT EXISTS partidos (
        id_partido INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

        id_liga INT NOT NULL,

        jornada INT NOT NULL,

        equipo_local VARCHAR(100) NOT NULL,
        equipo_visitante VARCHAR(100) NOT NULL,

        goles_local INT DEFAULT 0,
        goles_visitante INT DEFAULT 0,

        fecha_partido TIMESTAMP,

        estado VARCHAR(20) DEFAULT 'pendiente' CHECK (
          estado IN (
            'pendiente',
            'finalizado'
          )
        ),

        alineaciones JSONB NULL,

        premios_pagados BOOLEAN DEFAULT false,

        created_at TIMESTAMP DEFAULT NOW(),

        FOREIGN KEY (id_liga)
          REFERENCES ligas(id_liga)
          ON DELETE CASCADE
      );
    `);


    // 12. EVENTOS_PARTIDO
    await db.query(`
      CREATE TABLE IF NOT EXISTS eventos_partido (
        id_evento INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

        id_partido INT NOT NULL,

        minuto INT NOT NULL,
        tipo_evento VARCHAR(50) NOT NULL,

        id_futbolista INT NULL,
        id_asistente INT NULL,

        descripcion TEXT NOT NULL,

        created_at TIMESTAMP DEFAULT NOW(),

        FOREIGN KEY (id_partido)
          REFERENCES partidos(id_partido)
          ON DELETE CASCADE,

        FOREIGN KEY (id_futbolista)
          REFERENCES futbolistas(id_futbolista)
          ON DELETE SET NULL,

        FOREIGN KEY (id_asistente)
          REFERENCES futbolistas(id_futbolista)
          ON DELETE SET NULL
      );
    `);


    // 13. ALINEACIONES_JORNADA
    await db.query(`
      CREATE TABLE IF NOT EXISTS alineaciones_jornada (
        id_alineacion INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

        id_liga INT NOT NULL,
        jornada INT NOT NULL,
        id_user INT NOT NULL,

        id_futbolista INT NULL,

        hueco_plantilla VARCHAR(30) NOT NULL,
        es_hueco_vacio BOOLEAN DEFAULT false,

        tipo_carta_snapshot VARCHAR(30),
        nombre_snapshot VARCHAR(100),
        posicion_snapshot VARCHAR(50),
        media_snapshot INT,
        codigo_habilidad_snapshot VARCHAR(100),

        fecha_bloqueo TIMESTAMP DEFAULT NOW(),

        UNIQUE (id_liga, jornada, id_user, hueco_plantilla),

        FOREIGN KEY (id_liga)
          REFERENCES ligas(id_liga)
          ON DELETE CASCADE,

        FOREIGN KEY (id_user)
          REFERENCES users(id)
          ON DELETE CASCADE,

        FOREIGN KEY (id_futbolista)
          REFERENCES futbolistas(id_futbolista)
          ON DELETE SET NULL
      );
    `);


    // 14. RENDIMIENTO_PARTIDO
    await db.query(`
      CREATE TABLE IF NOT EXISTS rendimiento_partido (
        id_rendimiento INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

        id_partido INT NOT NULL,

        id_futbolista INT NULL,
        id_user INT NOT NULL,

        nota_base DECIMAL(3,1) NULL,

        puntos_totales INT DEFAULT 0,

        goles INT DEFAULT 0,
        asistencias INT DEFAULT 0,
        amarillas INT DEFAULT 0,
        rojas INT DEFAULT 0,

        goles_propia INT DEFAULT 0,
        mvp BOOLEAN DEFAULT false,
        porteria_cero BOOLEAN DEFAULT false,

        tipo_registro VARCHAR(30) DEFAULT 'jugador',
        hueco_plantilla VARCHAR(30),

        created_at TIMESTAMP DEFAULT NOW(),

        FOREIGN KEY (id_partido)
          REFERENCES partidos(id_partido)
          ON DELETE CASCADE,

        FOREIGN KEY (id_futbolista)
          REFERENCES futbolistas(id_futbolista)
          ON DELETE SET NULL,

        FOREIGN KEY (id_user)
          REFERENCES users(id)
          ON DELETE CASCADE
      );
    `);


    // 15. ÍNDICES Y CONTROLES ANTIDUPLICADO
    await db.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS ux_rendimiento_jugador
      ON rendimiento_partido (id_partido, id_user, id_futbolista)
      WHERE id_futbolista IS NOT NULL
        AND tipo_registro = 'jugador';
    `);

    await db.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS ux_rendimiento_hueco_vacio
      ON rendimiento_partido (id_partido, id_user, hueco_plantilla)
      WHERE tipo_registro = 'hueco_vacio';
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_partidos_liga_jornada
      ON partidos (id_liga, jornada);
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_rendimiento_partido_user
      ON rendimiento_partido (id_partido, id_user);
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_alineaciones_liga_jornada_user
      ON alineaciones_jornada (id_liga, jornada, id_user);
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_futbolista_user_liga_liga_user
      ON futbolista_user_liga (id_liga, id_user);
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_mercado_liga
      ON mercado_liga (id_liga);
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_pujas_liga_futbolista
      ON pujas (id_liga, id_futbolista);
    `);

    console.log('Tablas de Trébol League creadas/actualizadas correctamente');

  } catch (err) {
    console.error('Error creando tablas:', err);
  } finally {
    process.exit();
  }
}

initLeagueTables();