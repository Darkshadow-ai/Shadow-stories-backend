// Full Stack Storytelling Website (Backend & Frontend Setup)

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/storytelling', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected')).catch(err => console.log(err));

// User Schema & Model
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    role: { type: String, default: 'user' } // 'user' or 'admin'
});

const User = mongoose.model('User', UserSchema);

// Story Schema & Model
const StorySchema = new mongoose.Schema({
    title: String,
    content: String,
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});
const Story = mongoose.model('Story', StorySchema);

// User Registration
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res.json({ message: 'User registered' });
});

// User Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });
    res.json({ token, userId: user._id, username: user.username });
});

// Authentication Middleware
const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ error: 'No token, authorization denied' });
    try {
        const decoded = jwt.verify(token, 'secret');
        req.user = decoded.id;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Token is not valid' });
    }
};

// Post a Story (Authenticated Users Only)
app.post('/story', auth, async (req, res) => {
    const { title, content } = req.body;
    const newStory = new Story({ title, content, author: req.user });
    await newStory.save();
    res.json({ message: 'Story posted' });
});

// Get Stories
app.get('/stories', async (req, res) => {
    const stories = await Story.find().populate('author', 'username');
    res.json(stories);
});

// Get User Stories
app.get('/my-stories', auth, async (req, res) => {
    const stories = await Story.find({ author: req.user });
    res.json(stories);
});

// Delete Story (Only Author Can Delete)
app.delete('/story/:id', auth, async (req, res) => {
    const story = await Story.findById(req.params.id);
    if (!story) return res.status(404).json({ error: 'Story not found' });
    if (story.author.toString() !== req.user) return res.status(403).json({ error: 'Not authorized' });
    await Story.findByIdAndDelete(req.params.id);
    res.json({ message: 'Story deleted' });
});

// Serve Frontend Pages
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Basic Frontend Pages (HTML Files in 'public' Directory)
const fs = require('fs');
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir);
fs.writeFileSync(path.join(publicDir, 'index.html'), '<!DOCTYPE html><html><head><title>Stories</title></head><body><h1>Shadow Stories</h1><a href="/login.html">Login</a> | <a href="/dashboard.html">Dashboard</a></body></html>');
fs.writeFileSync(path.join(publicDir, 'login.html'), '<!DOCTYPE html><html><head><title>Login</title></head><body><h1>Login Page</h1></body></html>');
fs.writeFileSync(path.join(publicDir, 'dashboard.html'), '<!DOCTYPE html><html><head><title>Dashboard</title></head><body><h1>Dashboard</h1></body></html>');

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (await User.findOne({ email })) {
        return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });

    await newUser.save();
    res.json({ message: 'User registered successfully' });
});
app.put('/profile', async (req, res) => {
    const { username, password } = req.body;
    const userId = req.user.id;

    const updates = {};
    if (username) updates.username = username;
    if (password) updates.password = await bcrypt.hash(password, 10);

    await User.findByIdAndUpdate(userId, updates);
    res.json({ message: 'Profile updated' });
});

app.get('/admin/stories', async (req, res) => {
    const user = await User.findById(req.user.id);
    if (user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const stories = await Story.find();
    res.json(stories);
});



app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
