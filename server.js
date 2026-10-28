const express = require("express");
const session = require("express-session");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA = path.join(ROOT, "data");
const UPLOADS = path.join(ROOT, "public", "uploads");

fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(UPLOADS, { recursive: true });

const db = new Database(path.join(DATA, "md-shohagh.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS photos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'Style',
  filename TEXT NOT NULL,
  original_name TEXT NOT NULL,
  featured INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`);

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-this-password";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-session-secret";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" }
}));
app.use(express.static(path.join(ROOT, "public")));

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, crypto.randomUUID() + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ["image/jpeg","image/png","image/webp","image/gif"];
    cb(null, allowed.includes(file.mimetype));
  }
});

function auth(req, res, next) {
  if (!req.session.admin) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function safePhoto(row) {
  return { ...row, url: "/uploads/" + row.filename };
}

app.get("/api/photos", (req, res) => {
  const q = String(req.query.q || "").trim();
  const category = String(req.query.category || "").trim();

  let rows;
  if (q && category) {
    rows = db.prepare(`
      SELECT * FROM photos
      WHERE category = ? AND (title LIKE ? OR original_name LIKE ?)
      ORDER BY featured DESC, id DESC
    `).all(category, `%${q}%`, `%${q}%`);
  } else if (q) {
    rows = db.prepare(`
      SELECT * FROM photos
      WHERE title LIKE ? OR original_name LIKE ?
      ORDER BY featured DESC, id DESC
    `).all(`%${q}%`, `%${q}%`);
  } else if (category) {
    rows = db.prepare(`
      SELECT * FROM photos WHERE category = ?
      ORDER BY featured DESC, id DESC
    `).all(category);
  } else {
    rows = db.prepare(`
      SELECT * FROM photos ORDER BY featured DESC, id DESC
    `).all();
  }
  res.json(rows.map(safePhoto));
});

app.get("/api/categories", (_req, res) => {
  const rows = db.prepare("SELECT DISTINCT category FROM photos ORDER BY category").all();
  res.json(rows.map(x => x.category));
});

app.get("/api/me", (req, res) => {
  res.json({ admin: !!req.session.admin });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USER || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Wrong username or password" });
  }
  req.session.admin = true;
  res.json({ ok: true });
});

app.post("/api/logout", auth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.post("/api/photos", auth, upload.single("image"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Please select an image" });
  const title = String(req.body.title || req.file.originalname).trim().slice(0, 120);
  const category = String(req.body.category || "Style").trim().slice(0, 60) || "Style";
  const featured = req.body.featured === "true" ? 1 : 0;

  if (featured) db.prepare("UPDATE photos SET featured = 0").run();

  const info = db.prepare(`
    INSERT INTO photos (title, category, filename, original_name, featured)
    VALUES (?, ?, ?, ?, ?)
  `).run(title, category, req.file.filename, req.file.originalname, featured);

  const row = db.prepare("SELECT * FROM photos WHERE id = ?").get(info.lastInsertRowid);
  res.json(safePhoto(row));
});

app.put("/api/photos/:id", auth, (req, res) => {
  const id = Number(req.params.id);
  const current = db.prepare("SELECT * FROM photos WHERE id = ?").get(id);
  if (!current) return res.status(404).json({ error: "Photo not found" });

  const title = String(req.body.title ?? current.title).trim().slice(0, 120);
  const category = String(req.body.category ?? current.category).trim().slice(0, 60) || "Style";
  const featured = req.body.featured === true || req.body.featured === "true" ? 1 : 0;

  if (featured) db.prepare("UPDATE photos SET featured = 0").run();
  db.prepare("UPDATE photos SET title=?, category=?, featured=? WHERE id=?")
    .run(title, category, featured, id);

  res.json(safePhoto(db.prepare("SELECT * FROM photos WHERE id = ?").get(id)));
});

app.delete("/api/photos/:id", auth, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare("SELECT * FROM photos WHERE id = ?").get(id);
  if (!row) return res.status(404).json({ error: "Photo not found" });

  const file = path.join(UPLOADS, row.filename);
  if (fs.existsSync(file)) fs.unlinkSync(file);
  db.prepare("DELETE FROM photos WHERE id = ?").run(id);
  res.json({ ok: true });
});

app.get("/api/settings", (_req, res) => {
  const rows = db.prepare("SELECT key,value FROM settings").all();
  res.json(Object.fromEntries(rows.map(r => [r.key, r.value])));
});

app.put("/api/settings", auth, (req, res) => {
  const allowed = ["siteTitle", "tagline", "about"];
  const stmt = db.prepare(`
    INSERT INTO settings(key,value) VALUES(?,?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `);
  const tx = db.transaction(() => {
    for (const key of allowed) {
      if (req.body[key] !== undefined) stmt.run(key, String(req.body[key]).slice(0, 500));
    }
  });
  tx();
  res.json({ ok: true });
});

app.get("/admin", (_req, res) => {
  res.sendFile(path.join(ROOT, "public", "admin", "index.html"));
});

app.listen(PORT, () => {
  console.log(`MD Shohagh running on http://localhost:${PORT}`);
});
