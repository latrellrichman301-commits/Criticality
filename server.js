const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';

// Middleware to parse incoming form data correctly
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  dbName: 'CriticalityApp'
})
  .then(() => console.log('Connected to Database successfully.'))
  .catch(err => console.error('Database connection error:', err));

// Database Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  birthday: { type: String, required: true },
  isVerified: { type: Boolean, default: false }
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

// Nodemailer Transport Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Verify Gmail Connection on Boot
transporter.verify((error, success) => {
  if (error) {
    console.log('====================================');
    console.log('NODEMAILER GMAIL ERROR:', error.message);
    console.log('====================================');
  } else {
    console.log('====================================');
    console.log('Gmail is connected and ready to send emails! 🚀');
    console.log('====================================');
  }
});

// Signup Route
app.post('/api/signup', async (req, res) => {
  console.log('====================================');
  console.log('NEW SIGNUP ATTEMPT RECEIVED!');
  console.log('Data sent from browser:', req.body);
  console.log('====================================');

  try {
    const { username, email, password, birthday } = req.body;
    
    if (!username || !email || !password || !birthday) {
      console.log('🚨 REJECTED: Missing information from form.');
      return res.status(400).json({ message: 'Please fill out all fields.' });
    }

    const existingUser = await User.findOne({ username: username.toLowerCase() });
    if (existingUser) {
      console.log(`🚨 REJECTED: Username '${username}' is already taken!`);
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
    console.log(`✅ SUCCESS: User '${newUser.username}' saved to database.`);

    const domain = req.get('host');
    const protocol = req.protocol;
    const verificationLink = `${protocol}://${domain}/api/verify/${newUser._id}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Welcome to Criticality!',
      html: `
        <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333;">
          <p>hello, i glad you loggged into criticality</p>
          <br>
          <p>Click the link below to verify your account:</p>
          <p>
            <a href="${verificationLink}" target="_blank" style="padding: 10px 20px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
              Verify Email Address
            </a>
          </p>
          <br>
          <p style="font-size: 13px; color: #666;">Or copy this link into your browser:</p>
          <p style="font-size: 13px; color: #007bff; word-break: break-all;">${verificationLink}</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ SUCCESS: Verification email fired off to ${email}!`);

    res.status(201).json({ message: 'Verification sent to inbox' });
  } catch (error) {
    console.log('❌ CRITICAL SERVER ERROR:', error.message);
    res.status(500).json({ message: `Server error during signup: ${error.message}` });
  }
});

// Verification Endpoint
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

// Signin Route
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

// Fallback Route to serve SPA frontend
app.get(/(.*)/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server executing live over port: ${PORT}`);
});
