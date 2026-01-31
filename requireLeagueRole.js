const db = require('../db');

function requireLeagueRole(rolesPermitidos = []) {
  return async (req, res, next) => {
    const userId = req.user.id;
    const { id_liga } = req.params;

    const result = await db.query(
      `SELECT rol
       FROM users_liga
       WHERE id_user = $1 AND id_liga = $2`,
      [userId, id_liga]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({
        error: 'No perteneces a esta liga'
      });
    }

    const rolUsuario = result.rows[0].rol;

    if (!rolesPermitidos.includes(rolUsuario)) {
      return res.status(403).json({
        error: 'No tienes permisos suficientes'
      });
    }

    next();
  };
}

module.exports = requireLeagueRole;
