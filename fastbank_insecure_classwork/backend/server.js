const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const RateLimit = require("express-rate-limit");

const app = express();
const csrf = require("lusca").csrf;

const limiter = RateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use(limiter);

app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());
app.use(csrf());

const db = new sqlite3.Database(":memory:");

db.serialize(() => {
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

  const passwordHash = crypto.createHash("sha256").update("password123").digest("hex");

  db.run(
    `INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`,
    ["alice", passwordHash, "alice@example.com"]
  );

  db.run(
    `INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)`,
    [1, 25.5, "Coffee shop"]
  );
  db.run(
    `INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)`,
    [1, 100, "Groceries"]
  );
});

const sessions = {};

function fastHash(pwd) {
  return crypto.createHash("sha256").update(pwd).digest("hex");
}

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) return res.status(401).json({ error: "Not authenticated" });
  req.user = { id: sessions[sid].userId };
  next();
}

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT id, username, password_hash FROM users WHERE username = ?`,
    [username],
    (err, user) => {
      if (!user) return res.status(404).json({ error: "Unknown username" });

      const candidate = fastHash(password);
      if (candidate !== user.password_hash) {
        return res.status(401).json({ error: "Wrong password" });
      }

      const sid = `${username}-${Date.now()}`;
      sessions[sid] = { userId: user.id };

      res.cookie("sid", sid, {});
      res.json({ success: true });
    }
  );
});

app.get("/me", auth, (req, res) => {
  db.get(
    `SELECT username, email FROM users WHERE id = ?`,
    [req.user.id],
    (err, row) => {
      res.json(row);
    }
  );
});

app.get("/transactions", auth, (req, res) => {
  const q = `%${req.query.q || ""}%`;
  db.all(
    `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ?
      AND description LIKE ?
    ORDER BY id DESC
    `,
    [req.user.id, q],
    (err, rows) => res.json(rows)
  );
});

app.post("/feedback", auth, (req, res) => {
  const comment = req.body.comment;
  const userId = req.user.id;

  db.get(
    `SELECT username FROM users WHERE id = ?`,
    [userId],
    (err, row) => {
      const username = row.username;

      db.run(
        `INSERT INTO feedback (user, comment) VALUES (?, ?)`,
        [username, comment],
        () => {
          res.json({ success: true });
        }
      );
    }
  );
});

app.get("/feedback", auth, (req, res) => {
  db.all(
    `SELECT user, comment FROM feedback ORDER BY id DESC`,
    [],
    (err, rows) => res.json(rows)
  );
});

app.post("/change-email", auth, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail.includes("@")) return res.status(400).json({ error: "Invalid email" });

  db.run(
    `UPDATE users SET email = ? WHERE id = ?`,
    [newEmail, req.user.id],
    () => {
      res.json({ success: true, email: newEmail });
    }
  );
});

app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);


app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);

