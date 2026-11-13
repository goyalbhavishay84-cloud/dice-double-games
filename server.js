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

async function sendBrevoEmail({ toEmail, toName, subject, htmlContent }) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.EMAIL_USER || 'goyalbhavishay84@gmail.com';
  if (!apiKey) throw new Error('BREVO_API_KEY missing');
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'accept': 'application/json', 'api-key': apiKey, 'content-type': 'application/json' },
    body: JSON.stringify({
      sender: { name: 'Dice Double Games', email: senderEmail },
      to: [{ email: toEmail, name: toName || toEmail }],
      subject,
      htmlContent
    })
  });
  if (!res.ok) throw new Error(await res.text());
}

const otpStore = new Map();
const resetOtpStore = new Map();
const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, full_name TEXT, phone TEXT, email TEXT UNIQUE, password TEXT, balance REAL DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`ALTER TABLE users ADD COLUMN full_name TEXT`, () => {});
  db.run(`ALTER TABLE users ADD COLUMN phone TEXT`, () => {});
  db.run(`ALTER TABLE users ADD COLUMN email TEXT`, () => {});
  db.run(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, type TEXT, amount REAL, reference TEXT, status TEXT DEFAULT 'PENDING', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))`);
  db.run(`CREATE TABLE IF NOT EXISTS bets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, chosen_number INTEGER, rolled_number INTEGER, bet_amount REAL, payout REAL, outcome TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))`);
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
  if (req.headers['x-admin-key'] !== ADMIN_PASSKEY) return res.status(403).json({ error: 'Invalid Admin Key' });
  next();
}

app.post('/api/send-otp', (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid Email ID darj karein' });
  const cleanEmail = email.toLowerCase().trim();
  db.get(`SELECT id FROM users WHERE email = ?`, [cleanEmail], async (err, existing) => {
    if (existing) return res.status(400).json({ error: 'Ye Email ID pehle se registered hai' });
    const otp = crypto.randomInt(100000, 999999).toString();
    otpStore.set(cleanEmail, { otp, expiresAt: Date.now() + 600000 });
    try {
      await sendBrevoEmail({
        toEmail: cleanEmail,
        subject: 'Dice Double - Account Verification OTP',
        htmlContent: `<div style="font-family:Arial;padding:20px;background:#0f172a;color:#fff;border-radius:10px;"><h2 style="color:#38bdf8;">Dice Double OTP</h2><p>Aapka verification OTP:</p><div style="font-size:28px;font-weight:bold;letter-spacing:6px;color:#4ade80;margin:14px 0;">${otp}</div><p>10 minute me expire hoga.</p></div>`
      });
      res.json({ message: 'OTP aapke Email par bhej diya gaya hai! (Spam folder bhi check karein)' });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'OTP bhejne me dikkat aayi. BREVO_API_KEY check karein.' });
    }
  });
});

app.post('/api/forgot-password/send-otp', (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid registered Email ID darj karein' });
  const cleanEmail = email.toLowerCase().trim();
  db.get(`SELECT id, username FROM users WHERE email = ?`, [cleanEmail], async (err, user) => {
    if (!user) return res.status(404).json({ error: 'Is Email ID se koi account nahi mila' });
    const otp = crypto.randomInt(100000, 999999).toString();
    resetOtpStore.set(cleanEmail, { otp, expiresAt: Date.now() + 600000 });
    try {
      await sendBrevoEmail({
        toEmail: cleanEmail,
        toName: user.username,
        subject: 'Dice Double - Password Reset OTP',
        htmlContent: `<div style="font-family:Arial;padding:20px;background:#0f172a;color:#fff;border-radius:10px;"><h2 style="color:#38bdf8;">Password Reset OTP</h2><p>Hello <b>${user.username}</b>, password reset OTP:</p><div style="font-size:28px;font-weight:bold;letter-spacing:6px;color:#facc15;margin:14px 0;">${otp}</div><p>10 minute me expire hoga.</p></div>`
      });
      res.json({ message: 'Password reset OTP aapke Email par bhej diya gaya hai!' });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'OTP bhejne me dikkat aayi. BREVO_API_KEY check karein.' });
    }
  });
});

app.post('/api/forgot-password/reset', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) return res.status(400).json({ error: 'Email, OTP aur naya password bharna zaroori hai' });
  if (newPassword.length < 4) return res.status(400).json({ error: 'Password kam se kam 4 characters ka rakhein' });
  const cleanEmail = email.toLowerCase().trim();
  const record = resetOtpStore.get(cleanEmail);
  if (!record || record.otp !== otp.trim() || Date.now() > record.expiresAt) return res.status(400).json({ error: 'Galat ya expired Email OTP' });
  const hashed = await bcrypt.hash(newPassword, 10);
  db.run(`UPDATE users SET password = ? WHERE email = ?`, [hashed, cleanEmail], function (err) {
    if (err || this.changes === 0) return res.status(400).json({ error: 'Password update nahi ho paya' });
    resetOtpStore.delete(cleanEmail);
    res.json({ message: 'Password successfully reset ho gaya! Ab naye password se login karein.' });
  });
});

app.post('/api/register', async (req, res) => {
  const { fullName, phone, email, username, password, otp } = req.body;
  if (!fullName || !phone || !email || !username || !password || !otp) return res.status(400).json({ error: 'Saari details aur Email OTP bharna zaroori hai' });
  if (!/^\d{10}$/.test(phone.trim())) return res.status(400).json({ error: '10-digit ka valid mobile number darj karein' });
  const cleanEmail = email.toLowerCase().trim();
  const record = otpStore.get(cleanEmail);
  if (!record || record.otp !== otp.trim() || Date.now() > record.expiresAt) return res.status(400).json({ error: 'Galat ya expired Email OTP' });
  const hashed = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (username, full_name, phone, email, password, balance) VALUES (?, ?, ?, ?, ?, 0)`, [username.trim(), fullName.trim(), phone.trim(), cleanEmail, hashed], function (err) {
    if (err) return res.status(400).json({ error: 'Username ya Email pehle se maujood hai' });
    otpStore.delete(cleanEmail);
    const token = jwt.sign({ id: this.lastID, username: username.trim() }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: username.trim(), balance: 0 });
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username/Email aur password darj karein' });
  db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [username.trim(), username.toLowerCase().trim()], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username, balance: user.balance });
  });
});

app.get('/api/me', authenticateUser, (req, res) => {
  db.get(`SELECT id, username, full_name, phone, email, balance FROM users WHERE id = ?`, [req.userId], (err, user) => {
    db.all(`SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 15`, [req.userId], (err, txns) => {
      db.all(`SELECT * FROM bets WHERE user_id = ? ORDER BY id DESC LIMIT 15`, [req.userId], (err, bets) => {
        res.json({ user, transactions: txns, bets });
      });
    });
  });
});

app.post('/api/deposit', authenticateUser, (req, res) => {
  const { amount, utr } = req.body;
  if (!amount || amount <= 0 || !utr) return res.status(400).json({ error: 'Valid amount and UTR required' });
  db.run(`INSERT INTO transactions (user_id, type, amount, reference, status) VALUES (?, 'DEPOSIT', ?, ?, 'PENDING')`, [req.userId, amount, utr], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ message: 'Deposit request submitted for verification', id: this.lastID });
  });
});

app.post('/api/withdraw', authenticateUser, (req, res) => {
  const { amount, upiId } = req.body;
  if (!amount || amount <= 0 || !upiId) return res.status(400).json({ error: 'Valid amount and UPI/Bank details required' });
  db.get(`SELECT balance FROM users WHERE id = ?`, [req.userId], (err, user) => {
    if (!user || user.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
    db.serialize(() => {
      db.run(`UPDATE users SET balance = balance - ? WHERE id = ?`, [amount, req.userId]);
      db.run(`INSERT INTO transactions (user_id, type, amount, reference, status) VALUES (?, 'WITHDRAW', ?, ?, 'PENDING')`, [req.userId, amount, upiId], () => {
        res.json({ message: 'Withdrawal request submitted', newBalance: user.balance - amount });
      });
    });
  });
});

app.post('/api/roll', authenticateUser, (req, res) => {
  const num = parseInt(req.body.chosenNumber);
  const bet = parseFloat(req.body.betAmount);
  if (![1, 2, 3, 4, 5, 6].includes(num) || isNaN(bet) || bet <= 0) return res.status(400).json({ error: 'Invalid bet parameters' });
  db.get(`SELECT balance FROM users WHERE id = ?`, [req.userId], (err, user) => {
    if (!user || user.balance < bet) return res.status(400).json({ error: 'Insufficient balance' });
    const rolledNumber = crypto.randomInt(1, 7);
    const isWin = rolledNumber === num;
    const payout = isWin ? bet * 2 : 0;
    const newBalance = user.balance - bet + payout;
    db.serialize(() => {
      db.run(`UPDATE users SET balance = ? WHERE id = ?`, [newBalance, req.userId]);
      db.run(`INSERT INTO bets (user_id, chosen_number, rolled_number, bet_amount, payout, outcome) VALUES (?, ?, ?, ?, ?, ?)`, [req.userId, num, rolledNumber, bet, payout, isWin ? 'WIN' : 'LOSS']);
      res.json({ rolledNumber, outcome: isWin ? 'WIN' : 'LOSS', payout, newBalance });
    });
  });
});

app.get('/api/admin/dashboard', authenticateAdmin, (req, res) => {
  const stats = {};
  db.get(`SELECT SUM(amount) as total FROM transactions WHERE type='DEPOSIT' AND status='APPROVED'`, (err, dep) => {
    stats.totalDeposits = dep?.total || 0;
    db.get(`SELECT SUM(amount) as total FROM transactions WHERE type='WITHDRAW' AND status='APPROVED'`, (err, wit) => {
      stats.totalWithdrawals = wit?.total || 0;
      db.get(`SELECT SUM(bet_amount) as wagered, SUM(payout) as paid FROM bets`, (err, game) => {
        stats.totalWagered = game?.wagered || 0;
        stats.totalPayouts = game?.paid || 0;
        stats.houseProfit = stats.totalWagered - stats.totalPayouts;
        db.all(`SELECT t.*, u.username FROM transactions t JOIN users u ON t.user_id = u.id ORDER BY t.id DESC LIMIT 50`, (err, transactions) => {
          db.all(`SELECT id, username, full_name, phone, email, balance, created_at FROM users ORDER BY id DESC`, (err, users) => {
            db.all(`SELECT b.*, u.username FROM bets b JOIN users u ON b.user_id = u.id ORDER BY b.id DESC LIMIT 50`, (err, bets) => {
              res.json({ stats, transactions, users, bets });
            });
          });
        });
      });
    });
  });
});

app.post('/api/admin/transaction/:id', authenticateAdmin, (req, res) => {
  const { action } = req.body;
  const txnId = req.params.id;
  db.get(`SELECT * FROM transactions WHERE id = ?`, [txnId], (err, txn) => {
    if (!txn || txn.status !== 'PENDING') return res.status(400).json({ error: 'Transaction not found or already processed' });
    db.serialize(() => {
      db.run(`UPDATE transactions SET status = ? WHERE id = ?`, [action, txnId]);
      if (txn.type === 'DEPOSIT' && action === 'APPROVED') db.run(`UPDATE users SET balance = balance + ? WHERE id = ?`, [txn.amount, txn.user_id]);
      if (txn.type === 'WITHDRAW' && action === 'REJECTED') db.run(`UPDATE users SET balance = balance + ? WHERE id = ?`, [txn.amount, txn.user_id]);
      res.json({ message: `Transaction ${action}` });
    });
  });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
