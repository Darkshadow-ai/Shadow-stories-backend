require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.log(err));

// User Schema
const UserSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    role: { type: String, default: 'user' }
});
const User = mongoose.model('User', UserSchema);

// Story Schema
const StorySchema = new mongoose.Schema({
    title: String,
    content: String,
    userId: mongoose.Schema.Types.ObjectId,
    createdAt: { type: Date, default: Date.now }
});
const Story = mongoose.model('Story', StorySchema);

// Register User
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ error: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    res.json({ message: 'User registered successfully' });
});

// Login User
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// Middleware for Authentication
const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ error: 'Access denied' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        res.status(400).json({ error: 'Invalid token' });
    }
};

// Get Public Stories
app.get('/stories', async (req, res) => {
    const stories = await Story.find().sort({ createdAt: -1 });
    res.json(stories);
});

// Submit Story (Authenticated Users Only)
app.post('/story', auth, async (req, res) => {
    const { title, content } = req.body;
    const story = new Story({ title, content, userId: req.user.id });
    await story.save();
    res.json({ message: 'Story added' });
});

// Get User's Stories
app.get('/dashboard', auth, async (req, res) => {
    const stories = await Story.find({ userId: req.user.id });
    res.json(stories);
});

// Delete User Story
app.delete('/story/:id', auth, async (req, res) => {
    const story = await Story.findOne({ _id: req.params.id, userId: req.user.id });
    if (!story) return res.status(404).json({ error: 'Story not found' });

    await Story.deleteOne({ _id: req.params.id });
    res.json({ message: 'Story deleted' });
});

// Update Profile
app.put('/profile', auth, async (req, res) => {
    const { username, password } = req.body;
    const updates = {};
    if (username) updates.username = username;
    if (password) updates.password = await bcrypt.hash(password, 10);

    await User.findByIdAndUpdate(req.user.id, updates);
    res.json({ message: 'Profile updated' });
});

// Admin: Get All Stories
app.get('/admin/stories', auth, async (req, res) => {
    const user = await User.findById(req.user.id);
    if (user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    const stories = await Story.find();
    res.json(stories);
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
