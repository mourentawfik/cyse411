const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const csrf = require("csrf");
const helmet = require("helmet");
const { v4: uuidv4 } = require("uuid");
const rateLimit = require("express-rate-limit")

const app = express();

// --- BASIC CORS (clean, not vulnerable) ---
app.use(helmet());
app.use(
  cors({
   origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

// --- IN-MEMORY SQLITE DB (clean) ---
app.use(csrf({ cookie: true }));

const loginLimiter = rateLimit({ windowMs: 60_000, max: 5 });
const searchLimiter = rateLimit({ windowMs: 60_000, max: 20 });
const feedbackLimiter = rateLimit({ windowMs: 60_000, max: 10 });
const emailLimiter = rateLimit({ windowMs: 60_000, max: 5 });

const db = new sqlite3.Database(":memory:");

db.serialize(async() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT
    );
  `);

  db.run(`
    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      description TEXT
    );
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    );
  `);

  const hash = await bcrypt.hash("password123",12);

  db.run(`INSERT INTO users (username, password_hash, email)
          VALUES (?, ?, ?)`, ['alice', '${passwordHash}', 'alice@example.com'];`);

  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)`, [1, 25.50, 'Coffee shop']`);
  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)`, [1, 100, 'Groceries']`);
});

// --- SESSION STORE (simple, predictable token exactly like assignment) ---
const sessions = {};


function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) return res.status(401).json({ error: "Not authenticated" });
  req.user = { id: sessions[sid].userId };
  next();
}
function escapeHTML(str) {
  return str
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
// ------------------------------------------------------------
// Q4 — AUTH ISSUE 1 & 2: SHA256 fast hash + SQLi in username.
// Q4 — AUTH ISSUE 3: Username enumeration.
// Q4 — AUTH ISSUE 4: Predictable sessionId.
// ------------------------------------------------------------
app.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT id, username, password_hash FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (!user)
        return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match)
      return res.status(401).json({ error: "Invalid credentials" });
    

    const sid = uuidv4(); // predictable
    sessions[sid] = { userId: user.id };

    // Cookie is intentionally “normal” (not HttpOnly / secure)
    res.cookie("sid", sid, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict"
    });

    res.json({ success: true, csrfToken: req.csrfToken() });
    }
  });
});

// ------------------------------------------------------------
// /me — clean route, no vulnerabilities
// ------------------------------------------------------------
app.get("/me", auth, (req, res) => {
  db.get("SELECT username, email FROM users WHERE id = ?", [req.user.id], (err, row) => {
    res.json(row);
  });
});

// ------------------------------------------------------------
// Q1 — SQLi in transaction search
// ------------------------------------------------------------
app.get("/transactions", auth, searchLimiter, (req, res) => {
  const q = `%${req.query.q || ""}%;
  db.all(
    `SELECT id, amount, description
    FROM transactions
    WHERE user_id = ?
      AND description LIKE ?
    ORDER BY id DESC`,
    [req.user.id, q],
    (err, rows) => res.json(rows)
    );
});

// ------------------------------------------------------------
// Q2 — Stored XSS + SQLi in feedback insert
// ------------------------------------------------------------
app.post("/feedback", auth, feedbackLimiter, (req, res) => {
  const comment = escapeHTML(req.body.comment);


  db.get("SELECT username FROM users WHERE id = ?", [req.user.id], (err, row) => {
    const username = escapeHTML(row.username);

    db.run(`INSERT INTO feedback (user, comment) VALUES (?, ?)`,
      [username, comment],
      () => res.json({ success: true })
    );
  });
});

app.get("/feedback", auth, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    res.json(rows);
  });
});


app.post("/change-email", auth, emailLimiter, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail.includes("@")) 
  return res.status(400).json({ error: "Invalid email" });

  db.run(
    `UPDATE users SET email = ? WHERE id = ?`,
    [newEmail, req.user.id],
    () => {
      res.json({ success: true, email: newEmail });
      }
  );
});

app.listen(4000, () =>
  console.log("Seure FastBank backend running on http://localhost:4000")
);


