const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');

const app = express();
const port = 3000;
const secretKey = 'your-secret-key';

app.use(bodyParser.json());

// Public route
app.get('/api/data', (req, res) => {
  res.json({ message: 'This is public data' });
});

// Register route
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: "Todos los campos son obligatorios." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id",
            [username, email, hashedPassword]
        );

        res.status(201).json({ message: "Usuario registrado", userId: result.rows[0].id });
    } catch (error) {
        console.error("Error en /api/register:", error);
        res.status(500).json({ error: "Error al registrar usuario." });
    }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  try {
    // Find user
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Validate password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate token
    jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '30m' }, (err, token) => {
      if (err) {
        return res.status(500).json({ message: 'Error generating token' });
      }
      res.json({ token });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Protected route
app.get('/api/protected', verifyToken, (req, res) => {
  jwt.verify(req.token, secretKey, (err, authData) => {
    if (err) {
      res.sendStatus(403);
    } else {
      res.json({
        message: 'This is protected data',
        authData
      });
    }
  });
});

// Middleware para verificar token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined') {
    const bearer = bearerHeader.split(' ');
    const bearerToken = bearer[1];
    req.token = bearerToken;
    next();
  } else {
    res.sendStatus(403);
  }
}

app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});