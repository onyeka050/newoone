const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');
require('dotenv').config();

const app = express();
app.use(cors()); // Apply CORS middleware to enable cross-origin requests
app.use(express.json()); // Middleware to parse JSON bodies

// Register Endpoint
app.post('/register', async (req, res) => {
  console.log('Received registration request with body:', req.body);
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    console.log('Error: Missing fields during registration');
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    const query = 'INSERT INTO users (user_id, name, email, password) VALUES (?, ?, ?, ?)';
    db.query(query, [userId, name, email, hashedPassword], (err, results) => {
      if (err) {
        console.log('Database Error:', err);
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ error: 'Email already exists' });
        }
        return res.status(500).json({ error: 'Registration failed' });
      }
      console.log('Registration successful:', results);
      res.status(201).json({ message: 'User registered successfully' });
    });
  } catch (error) {
    console.log('Error hashing password:', error);
    res.status(500).json({ error: 'Error hashing password' });
  }
});

// Login Endpoint
app.post('/login', async (req, res) => {
  console.log('Received login request with body:', req.body);
  const { email, password } = req.body;

  if (!email || !password) {
    console.log('Error: Missing fields during login');
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      console.log('Database Error on login:', err);
      return res.status(500).json({ error: 'Login failed' });
    }
    
    if (results.length === 0) {
      console.log('Login error: Invalid email');
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Login error: Invalid password');
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    console.log('Login successful:', user);
    res.status(200).json({ message: 'Login successful', userId: user.user_id });
  });
});

// Listening on environment-specified port or 5001
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
