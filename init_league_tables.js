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
        dinero NUMERIC(10,2) DEFAULT 0,
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
        precio INT NOT NULL DEFAULT 20000
      );
    `);

    // 4. Tabla de Puntuaciones por Jornada
    await db.query(`
      CREATE TABLE IF NOT EXISTS puntuacion (
        id_futbolista INT,
        jornada INT,
        puntos INT,
        PRIMARY KEY (id_futbolista, jornada),
        FOREIGN KEY (id_futbolista)
          REFERENCES futbolistas(id_futbolista) ON DELETE CASCADE
      );
    `);

    // 5. Relación Futbolista - Usuario - Liga (PLANTILLA)
    // AQUI ESTAN LOS CAMBIOS: Añadidas columnas en_venta y precio_venta
    await db.query(`
      CREATE TABLE IF NOT EXISTS futbolista_user_liga (
        id_user INT,
        id_liga INT,
        id_futbolista INT,
        en_venta BOOLEAN DEFAULT FALSE,
        precio_venta NUMERIC(15,2) DEFAULT 0,
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
        monto NUMERIC(15,2) NOT NULL,
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
        monto NUMERIC(15,2) NOT NULL,
        fecha TIMESTAMP DEFAULT NOW(),
        tipo VARCHAR(20) CHECK (tipo IN ('compra_mercado', 'compra_usuario', 'venta_rapida')),
        FOREIGN KEY (id_liga) REFERENCES ligas(id_liga) ON DELETE CASCADE,
        FOREIGN KEY (id_futbolista) REFERENCES futbolistas(id_futbolista) ON DELETE CASCADE
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