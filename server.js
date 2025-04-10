const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const session = require('express-session');

// Import the User model
const User = require('./models/User');  // Path to the User model

// Load environment variables
dotenv.config();

// Initialize Express
const app = express();
app.use(express.json()); // For parsing JSON requests
app.use(cors()); // Enable CORS

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// User registration route
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Check if the user already exists by email
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the user's password before saving it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user instance
    const newUser = new User({
      username,
      email,
      password: hashedPassword
    });

    // Save the new user to the database
    await newUser.save();

    // Respond with the new user's data (excluding the password)
    res.status(201).json({
      message: 'User registered successfully',
      user: { username: newUser.username, email: newUser.email }
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err });
  }
});

// User login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Compare the password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Generate a JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Respond with the token
    res.json({
      message: 'Login successful',
      token
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err });
  }
});

// Middleware to verify the JWT token (for protected routes)
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ message: 'Access denied' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Protected route to get user profile (requires authentication)
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    // Find the user by ID (using the userId from the token)
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Respond with the user data (excluding password)
    res.json({
      username: user.username,
      email: user.email,
      createdAt: user.createdAt
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err });
  }
});

// Logout route (for session management)
app.post('/logout', (req, res) => {
  // Destroy the session or token on the client side (depending on your strategy)
  // For JWT, the token should be deleted on the client side
  res.json({ message: 'Logged out successfully' });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
