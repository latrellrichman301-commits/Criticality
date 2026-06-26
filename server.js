const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'criticality_super_secret_key';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/criticality';

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Connection
mongoose.connect(MONGO_URI)
    .then(() => console.log('Connected to Database successfully.'))
    .catch(err => console.error('Database connection error:', err));

// User Data Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, minlength: 3 },
    password: { type: String, required: true },
    birthday: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// API Route: Sign Up
app.post('/api/signup', async (req, res) => {
    try {
        const { username, password, month, day, year } = req.body;

        if (!username || !password || !month || !day || !year) {
            return res.status(400).json({ message: 'All registration fields are required.' });
        }

        const userExists = await User.findOne({ username: { $regex: new RegExp(`^${username}$`, 'i') } });
        if (userExists) {
            return res.status(400).json({ message: 'Username is already taken.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const birthday = `${year}-${month}-${day}`;

        const newUser = new User({
            username,
            password: hashedPassword,
            birthday
        });

        await newUser.save();
        res.status(201).json({ message: 'Account successfully created!' });

    } catch (error) {
        res.status(500).json({ message: 'Internal server initialization error.' });
    }
});

// API Route: Sign In
app.post('/api/signin', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });

        res.status(200).json({ message: 'Login successful!', token });

    } catch (error) {
        res.status(500).json({ message: 'Internal server authentication error.' });
    }
});

// Wildcard routing to default back home
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server executing live over port: ${PORT}`);
});
