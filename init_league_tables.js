const db = require('./db');

async function initLeagueTables() {
  try {

    // 1. Tabla de Ligas
    await db.query(`
      CREATE TABLE IF NOT EXISTS ligas (
        id_liga INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        numero_jugadores INT NOT NULL DEFAULT 0,
        max_jugadores INT NOT NULL,
        clave VARCHAR(8) NOT NULL
      );
    `);

    // 2. Tabla de Usuarios en Ligas (Dinero, Puntos, Rol)
    await db.query(`
      CREATE TABLE IF NOT EXISTS users_liga (
        id_user INT,
        id_liga INT,
        dinero BIGINT DEFAULT 0,
        puntos INT DEFAULT 0,
        rol VARCHAR(20) NOT NULL DEFAULT 'user',
        PRIMARY KEY (id_user, id_liga),
        FOREIGN KEY (id_user) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (id_liga) REFERENCES ligas(id_liga) ON DELETE CASCADE
      );
    `);

    // 3. Tabla de Futbolistas (Datos generales)
    await db.query(`
      CREATE TABLE IF NOT EXISTS futbolistas (
        id_futbolista INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        posicion VARCHAR(50) NOT NULL,
        equipo VARCHAR(100) NOT NULL,
        media INT,
        precio INT NOT NULL DEFAULT 20000,
        imagen VARCHAR(255),
        ataque INT DEFAULT 0,
        defensa INT DEFAULT 0,
        pase INT DEFAULT 0,
        parada INT DEFAULT 0
      );
    `);

    // 5. Relación Futbolista - Usuario - Liga (PLANTILLA)
    await db.query(`
      CREATE TABLE IF NOT EXISTS futbolista_user_liga (
        id_user INT,
        id_liga INT,
        id_futbolista INT,
        en_venta BOOLEAN DEFAULT FALSE,
        precio_venta BIGINT DEFAULT 0,
        PRIMARY KEY (id_user, id_liga, id_futbolista),
        FOREIGN KEY (id_user, id_liga)
          REFERENCES users_liga(id_user, id_liga) ON DELETE CASCADE,
        FOREIGN KEY (id_futbolista)
          REFERENCES futbolistas(id_futbolista) ON DELETE CASCADE
      );
    `);

    // 6. Mercado Diario (La Banca)
    await db.query(`
      CREATE TABLE IF NOT EXISTS mercado_liga (
        id_liga INT,
        id_futbolista INT,
        fecha_generacion TIMESTAMP NOT NULL,
        PRIMARY KEY (id_liga, id_futbolista),
        FOREIGN KEY (id_liga) REFERENCES ligas(id_liga) ON DELETE CASCADE,
        FOREIGN KEY (id_futbolista) REFERENCES futbolistas(id_futbolista) ON DELETE CASCADE
      );  
    `);

    // 7. Tabla de Pujas (Ofertas al mercado)
    await db.query(`
      CREATE TABLE IF NOT EXISTS pujas (
        id_puja INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        id_liga INT,
        id_futbolista INT,
        id_user INT,
        monto BIGINT NOT NULL,
        fecha TIMESTAMP DEFAULT NOW(),
        FOREIGN KEY (id_liga) REFERENCES ligas(id_liga) ON DELETE CASCADE,
        FOREIGN KEY (id_futbolista) REFERENCES futbolistas(id_futbolista) ON DELETE CASCADE,
        FOREIGN KEY (id_user) REFERENCES users(id) ON DELETE CASCADE
      );
    `);

    // 8. Historial de Transferencias (Feed de noticias)
    await db.query(`
      CREATE TABLE IF NOT EXISTS historial_transferencias (
        id_historial INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        id_liga INT,
        id_futbolista INT,
        id_vendedor INT, -- Puede ser NULL si vende el sistema (Mercado)
        id_comprador INT, -- Puede ser NULL si vende al sistema (Venta rápida)
        monto BIGINT NOT NULL,
        fecha TIMESTAMP DEFAULT NOW(),
        tipo VARCHAR(20) CHECK (tipo IN ('compra_mercado', 'compra_usuario', 'venta_rapida')),
        FOREIGN KEY (id_liga) REFERENCES ligas(id_liga) ON DELETE CASCADE,
        FOREIGN KEY (id_futbolista) REFERENCES futbolistas(id_futbolista) ON DELETE CASCADE
      );
    `);

    // 9. Tabla de Ofertas Privadas (Ofertas a los rivales)
    await db.query(`
      CREATE TABLE IF NOT EXISTS ofertas_privadas (
          id_oferta INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          id_liga INT NOT NULL,
          id_futbolista INT NOT NULL,
          id_comprador INT NOT NULL,  -- El que hace la oferta
          id_vendedor INT NOT NULL,   -- El dueño actual del jugador
          monto BIGINT NOT NULL,      -- El dinero que se ofrece
          estado VARCHAR(20) DEFAULT 'pendiente', -- 'pendiente', 'aceptada', 'rechazada'
          fecha_creacion TIMESTAMP DEFAULT NOW(),
          
          FOREIGN KEY (id_liga) REFERENCES ligas(id_liga) ON DELETE CASCADE,
          FOREIGN KEY (id_futbolista) REFERENCES futbolistas(id_futbolista) ON DELETE CASCADE,
          FOREIGN KEY (id_comprador) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY (id_vendedor) REFERENCES users(id) ON DELETE CASCADE
      );
    `);

      // 10. Tabla de Partidos (El Calendario)
    await db.query(`
      CREATE TABLE IF NOT EXISTS partidos (
          id_partido INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          id_liga INT NOT NULL, -- Seguimos dejándolo por si cada liga privada va a su ritmo
          jornada INT NOT NULL,
          equipo_local VARCHAR(100) NOT NULL,      -- Ej: 'Real Pinar FC'
          equipo_visitante VARCHAR(100) NOT NULL,  -- Ej: 'Neón City FC'
          goles_local INT DEFAULT 0,
          goles_visitante INT DEFAULT 0,
          fecha_partido TIMESTAMP,
          estado VARCHAR(20) DEFAULT 'pendiente', 
          
          FOREIGN KEY (id_liga) REFERENCES ligas(id_liga) ON DELETE CASCADE
      );
    `);

    // 11. Tabla de Eventos (El "Minuto a Minuto" de los 60 mins)
    await db.query(`
      CREATE TABLE IF NOT EXISTS eventos_partido (
          id_evento INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          id_partido INT NOT NULL,
          minuto INT NOT NULL,
          tipo_evento VARCHAR(50) NOT NULL,
          id_futbolista INT,
          id_asistente INT,
          descripcion TEXT NOT NULL,
          
          FOREIGN KEY (id_partido) REFERENCES partidos(id_partido) ON DELETE CASCADE,
          FOREIGN KEY (id_futbolista) REFERENCES futbolistas(id_futbolista) ON DELETE SET NULL,
          FOREIGN KEY (id_asistente) REFERENCES futbolistas(id_futbolista) ON DELETE SET NULL
      );
    `);

    // 12. Rendimiento del Jugador
    // Aquí guardamos el desglose exacto de por qué ha sumado o restado puntos
    await db.query(`
      CREATE TABLE IF NOT EXISTS rendimiento_partido (
          id_rendimiento INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          id_partido INT NOT NULL,
          id_futbolista INT NOT NULL,
          id_user INT NOT NULL,
          
          nota_base DECIMAL(3,1) DEFAULT 6.0,
          puntos_totales INT DEFAULT 0,
          goles INT DEFAULT 0,
          asistencias INT DEFAULT 0,
          amarillas INT DEFAULT 0,
          rojas INT DEFAULT 0,
          goles_propia INT DEFAULT 0,
          mvp BOOLEAN DEFAULT FALSE,
          porteria_cero BOOLEAN DEFAULT FALSE,
          
          FOREIGN KEY (id_partido) REFERENCES partidos(id_partido) ON DELETE CASCADE,
          FOREIGN KEY (id_futbolista) REFERENCES futbolistas(id_futbolista) ON DELETE CASCADE,
          FOREIGN KEY (id_user) REFERENCES users(id) ON DELETE CASCADE
      );
    `);

    console.log('Tablas de Trebol League creadas/actualizadas correctamente');

  } catch (err) {
    console.error('Error creando tablas:', err);
  } finally {
    process.exit();
  }
}

initLeagueTables();