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
