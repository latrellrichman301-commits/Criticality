const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(process.env.MONGO_URI, {
  dbName: 'CriticalityApp'
})
  .then(() => console.log('Connected to Database successfully.'))
  .catch(err => console.error('Database connection error:', err));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  birthday: { type: String, required: true },
  isVerified: { type: Boolean, default: false }
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password, birthday } = req.body;
    
    const existingUser = await User.findOne({ username: username.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username: username.toLowerCase(),
      email,
      password: hashedPassword,
      birthday,
      isVerified: false
    });

    await newUser.save();

    const domain = req.get('host');
    const protocol = req.protocol;
    console.log('\n====================================');
    console.log(`NEW SIGNUP FOR: ${username}`);
    console.log(`CLICK THIS LINK TO VERIFY EMAIL: ${protocol}://${domain}/api/verify/${newUser._id}`);
    console.log('====================================\n');

    res.status(201).json({ message: 'Verification sent to inbox' });
  } catch (error) {
    res.status(500).json({ message: 'Server error during signup' });
  }
});

app.get('/api/verify/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send('<h1>Verification Failed</h1><p>User not found.</p>');
    }

    user.isVerified = true;
    await user.save();

    res.send('<h1>Email Verified Successfully!</h1><p>You can now close this tab, go back to Criticality, and log in.</p>');
  } catch (error) {
    res.status(500).send('<h1>Server Error</h1><p>Could not verify email.</p>');
  }
});

app.post('/api/signin', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username: username.toLowerCase() });
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(400).json({ message: 'Please verify your email address before logging in.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ message: 'Login successful!', token });
  } catch (error) {
    res.status(500).json({ message: 'Server error during signin' });
  }
});

app.get(/(.*)/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server executing live over port: ${PORT}`);
});
