const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_TO_A_STRONG_SECRET_KEY';
const ADMIN_PASSKEY = 'bhavishay@123';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helper: Send Email via Brevo HTTPS API (Never blocked on Render)
async function sendBrevoEmail({ toEmail, toName, subject, htmlContent }) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.EMAIL_USER || 'goyalbhavishay84@gmail.com';

  if (!apiKey) {
    throw new Error('BREVO_API_KEY missing in Render Environment');
  }

  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': apiKey,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      sender: { name: 'Dice Double Games', email: senderEmail },
      to: [{ email: toEmail, name: toName || toEmail }],
      subject,
      htmlContent
    })
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Brevo API Error: ${errText}`);
  }
}

// Temporary in-memory OTP stores: { email: { otp, expiresAt } }
const otpStore = new Map();
const resetOtpStore = new Map();

// Database Setup
const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    full_name TEXT,
    phone TEXT,
    email TEXT UNIQUE,
    password TEXT,
    balance REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`ALTER TABLE users ADD COLUMN full_name TEXT`, () => {});
  db.run(`ALTER TABLE users ADD COLUMN phone TEXT`, () => {});
  db.run(`ALTER TABLE users ADD COLUMN email TEXT`, () => {});

  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT,
    amount REAL,
    reference TEXT,
    status TEXT DEFAULT 'PENDING',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS bets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    chosen_number INTEGER,
    rolled_number INTEGER,
    bet_amount REAL,
    payout REAL,
    outcome TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

function authenticateUser(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.userId = decoded.id;
    next();
  });
}

function authenticateAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (key !== ADMIN_PASSKEY) {
    return res.status(403).json({ error: 'Invalid Admin Key' });
  }
  next();
}

// ================= AUTH, OTP & FORGOT PASSWORD ROUTES =================

// Send Email OTP for Signup
app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid Email ID darj karein' });
  }

  db.get(`SELECT id FROM users WHERE email = ?`, [email.toLowerCase().trim()], async (err, existing) => {
    if (existing) {
      return res.status(400).json({ error: 'Ye Email ID pehle se registered hai' });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    otpStore.set(email.toLowerCase().trim(), {
      otp,
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    try {
      await sendBrevoEmail({
        toEmail: email.trim(),
        subject: 'Dice Double - Account Verification OTP',
        htmlContent: `
          <div style="font-family:Arial,sans-serif;padding:20px;background:#0f172a;color:#f8fafc;border-radius:10px;">
            <h2 style="color:#38bdf8;">🎲 Dice Double Account Verification</h2>
            <p>Aapka naya account verify karne ke liye OTP niche diya gaya hai:</p>
            <div style="font-size:28px;font-weight:bold;letter-spacing:6px;color:#4ade80;margin:16px 0;">${otp}</div>
            <p style="color:#94a3b8;font-size:13px;">Ye OTP 10 minute ke liye valid hai.</p>
          </div>
        `
      });
      res.json({ message: 'OTP aapke Email par bhej diya gaya hai! (Spam folder bhi check karein)' });
    } catch (mailErr) {
      console.error('Brevo Mail error:', mailErr);
      res.status(500).json({ error: 'OTP bhejne me dikkat aayi. Render par BREVO_API_KEY check karein.' });
    }
  });
});

// Send Email OTP for Forgot Password
app.post('/api/forgot-password/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid registered Email ID darj karein' });
  }

  db.get(`SELECT id, username FROM users WHERE email = ?`, [email.toLowerCase().trim()], async (err, user) => {
    if (!user) {
      return res.status(404).json({ error: 'Is Email ID se koi account nahi mila' });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    resetOtpStore.set(email.toLowerCase().trim(), {
      otp,
      expiresAt: Date.now() + 10 * 60 * 1000
    });

    try {
      await sendBrevoEmail({
        toEmail: email.trim(),
        toName: user.username,
        subject: 'Dice Double - Password Reset OTP',
        htmlContent: `
          <div style="font-family:Arial,sans-serif;padding:20px;background:#0f172a;color:#f8fafc;border-radius:10px;">
            <h2 style="color:#38bdf8;">🔐 Password Reset Request</h2>
            <p>Hello <b>${user.username}</b>, password reset karne ke liye OTP niche diya gaya hai:</p>
            <div style="font-size:28px;font-weight:bold;letter-spacing:6px;color:#facc15;margin:16px 0;">${otp}</div>
            <p style="color:#94a3b8;font-size:13px;">Ye OTP 10 minute ke liye valid hai.</p>
          </div>
        `
      });
      res.json({ message: 'Password reset OTP aapke Email par bhej diya gaya hai!' });
    } catch (mailErr) {
      console.error('Brevo Reset error:', mailErr);
      res.status(500).json({ error: 'OTP bhejne me dikkat aayi. BREVO_API_KEY check karein.' });
    }
  });
});

// Verify OTP & Reset Password
app.post('/api/forgot-password/reset', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) {
    return res.status(400).json({ error: 'Email, OTP aur naya password bharna zaroori hai' });
  }

  if (newPassword.length < 4) {
    return res.status(400).json({ error: 'Password kam se kam 4 characters ka rakhein' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const record = resetOtpStore.get(cleanEmail);
  if (!record || record.otp !== otp.trim() || Date.now() > record.expiresAt) {
    return res.status(400).json({ error: 'Galat ya expired Email OTP' });
  }

  const hashed = await bcrypt.hash(newPassword, 10);
  db.run(`UPDATE users SET password = ? WHERE email = ?`, [hashed, cleanEmail], function (err) {
    if (err || this.changes === 0) {
      return res.status(400).json({ error: 'Password update nahi ho paya' });
    }
    resetOtpStore.delete(cleanEmail);
    res.json({ message: 'Password successfully reset ho gaya! Ab naye password se login karein.' });
  });
});

// Register with Email OTP Verification
app.post('/api/register', async (req, res) => {
  const { fullName, phone, email, username, password, otp } = req.body;

  if (!fullName || !phone || !email || !username || !password || !otp) {
    return res.status(400).json({ error: 'Saari details aur Email OTP bharna zaroori hai' });
  }

  if (!/^\d{10}$/.test(phone.trim())) {
    return res.status(400).json({ error: '10-digit ka valid mobile number darj karein' });
  }

  const record = otpStore.get(email.toLowerCase().trim());
  if (!record || record.otp !== otp.trim() || Date.now() > record.expiresAt) {
    return res.status(400).json({ error: 'Galat ya expired Email OTP' });
  }

  const hashed = await bcrypt.hash(password, 10);
  db.run(
    `INSERT INTO users (username, full_name, phone, email, password, balance) VALUES (?, ?, ?, ?, ?, 0)`,
    [username.trim(), fullName.trim(), phone.trim(), email.toLowerCase().trim(), hashed],
    function (err) {
      if (err) {
        return res.status(400).json({ error: 'Username ya Email pehle se maujood hai' });
      }
      otpStore.delete(email.toLowerCase().trim());
      const token = jwt.sign({ id: this.lastID, username: username.trim() }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, username: username.trim(), balance: 0 });
    }
  );
});

// Login (Supports Username or Email)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username/Email aur password darj karein' });

  db.get(
    `SELECT * FROM users WHERE username = ? OR email = ?`,
    [username.trim(), username.toLowerCase().trim()],
    async (err, user) => {
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, username: user.username, balance: user.balance });
    }
  );
});

// ================= USER ROUTES =================

app.get('/api/me', authenticateUser, (req, res) => {
  db.get(`SELECT id, username, full_name, phone, email, balance FROM users WHERE id = ?`, [req.userId], (err, user) => {
    db.all(`SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 15`, [req.userId], (err, txns) => {
      db.all(`SELECT * FROM bets WHERE user_id = ? ORDER BY id DESC LIMIT 15`, [req.userId], (err, bets) => {
        res.json({ user, transactions: txns, bets });
      });
