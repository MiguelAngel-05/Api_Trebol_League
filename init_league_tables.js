const db = require('./db');

async function initLeagueTables() {
  try {

    await db.query(`
      CREATE TABLE IF NOT EXISTS ligas (
        id_liga INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        numero_jugadores INT NOT NULL DEFAULT 0,
        max_jugadores INT NOT NULL,
        clave VARCHAR(8) NOT NULL
      );
    `);

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

    await db.query(`
      CREATE TABLE IF NOT EXISTS futbolistas (
        id_futbolista INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        posicion VARCHAR(50) NOT NULL,
        dorsal INT,
        precio INT NOT NULL DEFAULT 20000
      );
    `);

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

    await db.query(`
      CREATE TABLE IF NOT EXISTS futbolista_user_liga (
        id_user INT,
        id_liga INT,
        id_futbolista INT,
        PRIMARY KEY (id_user, id_liga, id_futbolista),
        FOREIGN KEY (id_user, id_liga)
          REFERENCES users_liga(id_user, id_liga) ON DELETE CASCADE,
        FOREIGN KEY (id_futbolista)
          REFERENCES futbolistas(id_futbolista) ON DELETE CASCADE
      );
    `);

    console.log('Tablas de Trebol League creadas correctamente');

  } catch (err) {
    console.error('Error creando tablas:', err);
  } finally {
    process.exit();
  }
}

initLeagueTables();
