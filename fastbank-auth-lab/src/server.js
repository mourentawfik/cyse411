const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
// bcrypt is installed but NOT used in the vulnerable baseline:
const bcrypt = require("bcrypt");
const csrf = require("csurf")

const app = express();
const PORT = 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

/**
 * VULNERABLE FAKE USER DB
 * For simplicity, we start with a single user whose password is "password123".
 * In the vulnerable version, we hash with a fast hash (SHA-256-like).
 */
const users = [
  {
    id: 1,
    username: "student",
    // VULNERABLE: fast hash without salt
    passwordHash: bcrypt.hashSync("password123", 10) // students must replace this scheme with bcrypt
  }
];

// In-memory session store
const sessions = {}; // token -> { userId }

/**
 * VULNERABLE FAST HASH FUNCTION
 * Students MUST STOP using this and replace logic with bcrypt.
 */
}

// Helper: find user by username
function findUser(username) {
  return users.find((u) => u.username === username);
}

// Home API just to show who is logged in
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false, csrfToken: req.csrfToken() });
  }
  // const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username, csrfToken: req.csrfToken() });
});

/**
 * VULNERABLE LOGIN ENDPOINT
 * - Uses fastHash instead of bcrypt
 * - Error messages leak whether username exists
 * - Session token is simple and predictable
 * - Cookie lacks security flags
 */
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  const authFail = () =>
    res.status(401).json({ success: false, message: "Invalid credentials" });
  
  if (!user) return authFail();
  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) return authFail();

  const token = crypto.randomBytes(32).toString("hex");
  sessions[token] = { userId: user.id };

  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax"
  });

  // Client-side JS (login.html) will store this token in localStorage (vulnerable)
  res.json({ success: true, csrfToken: req.csrftToken() });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) delete sessions[token];
  
  res.clearCookie("session");
  res.json({ success: true, csrfToken: req.csrfToken() });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
