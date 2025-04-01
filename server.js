const express = require("express"); const mongoose = require("mongoose"); const jwt = require("jsonwebtoken"); const cors = require("cors"); const bcrypt = require("bcryptjs"); require("dotenv").config();

const app = express(); app.use(express.json()); app.use(cors());

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true, });

const UserSchema = new mongoose.Schema({ username: String, password: String, }); const StorySchema = new mongoose.Schema({ category: String, text: String, authorName: String, authorId: mongoose.Schema.Types.ObjectId, });

const User = mongoose.model("User", UserSchema); const Story = mongoose.model("Story", StorySchema);

app.post("/register", async (req, res) => { const { username, password } = req.body; const hashedPassword = await bcrypt.hash(password, 10); const user = new User({ username, password: hashedPassword }); await user.save(); res.json({ message: "User registered" }); });

app.post("/login", async (req, res) => { const { username, password } = req.body; const user = await User.findOne({ username }); if (!user || !(await bcrypt.compare(password, user.password))) { return res.status(401).json({ message: "Invalid credentials" }); } const token = jwt.sign({ userId: user._id, username }, process.env.JWT_SECRET); res.json({ token }); });

const authMiddleware = (req, res, next) => { const token = req.headers.authorization; if (!token) return res.status(401).json({ message: "Unauthorized" }); try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); } catch { res.status(401).json({ message: "Invalid token" }); } };

app.post("/stories", authMiddleware, async (req, res) => { const { category, text } = req.body; const story = new Story({ category, text, authorName: req.user.username, authorId: req.user.userId, }); await story.save(); res.json({ message: "Story submitted" }); });

app.get("/stories", async (req, res) => { const stories = await Story.find(); res.json(stories); });

app.get("/mystories", authMiddleware, async (req, res) => { const stories = await Story.find({ authorId: req.user.userId }); res.json(stories); });

const PORT = process.env.PORT || 3000; app.listen(PORT, () => console.log(Server running on port ${PORT}));

