const db = require('./db');

async function migrate() {
    try {
        await db.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS username VARCHAR(255) UNIQUE;
    `);
        console.log('Column "username" added successfully.');
    } catch (err) {
        console.error('Error adding column:', err);
    } finally {
        setTimeout(() => process.exit(), 1000);
    }
}

migrate();