import express from "express";
import cors from "cors";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";
const FRONTEND_DIR = path.resolve(__dirname, "../frontend");
const CORS_ORIGIN = process.env.CORS_ORIGIN || "";
const STORAGE_ROOT = path.resolve(process.env.STORAGE_DIR || path.join(__dirname, "storage"));

const corsOptions = CORS_ORIGIN
  ? {
      origin: CORS_ORIGIN.split(",").map((origin) => origin.trim()).filter(Boolean)
    }
  : true;

app.use(cors(corsOptions));
app.use(express.json());

const uploadsDir = path.join(STORAGE_ROOT, "uploads");
const dbPath = path.join(STORAGE_ROOT, "db.json");

fs.mkdirSync(STORAGE_ROOT, { recursive: true });
fs.mkdirSync(uploadsDir, { recursive: true });

app.use("/uploads", express.static(uploadsDir));
app.use(express.static(FRONTEND_DIR));

const seed = {
  users: [
    {
      id: "admin_1",
      username: "admin",
      password: "admin",
      role: "admin",
      email: "admin@greenstep.local",
      city: "Москва",
      age: "",
      goal: "Управлять платформой",
      bio: "Системный администратор",
      transport: "",
      diet: "",
      recycling: "",
      createdAt: new Date().toISOString()
    },
    {
      id: "user_demo_1",
      username: "Алина",
      password: "123456",
      role: "user",
      email: "alina@example.com",
      city: "Москва",
      age: "21",
      goal: "Снизить использование пластика",
      bio: "Хочу выработать экологичные привычки",
      transport: "Метро и пешком",
      diet: "Смешанное",
      recycling: "Сортирую пластик и бумагу",
      createdAt: new Date().toISOString()
    }
  ],
  challenges: [
    {
      id: "challenge_demo_1",
      title: "7 дней без одноразового пластика",
      reward: 150,
      category: "Потребление",
      difficulty: "Средний",
      description: "Используй многоразовые альтернативы и загрузи фото результата.",
      active: true,
      assignedUserIds: [],
      createdAt: new Date().toISOString()
    },
    {
      id: "challenge_demo_2",
      title: "3 поездки без автомобиля",
      reward: 200,
      category: "Транспорт",
      difficulty: "Средний",
      description: "Выбирай пешие маршруты, велосипед или общественный транспорт.",
      active: true,
      assignedUserIds: [],
      createdAt: new Date().toISOString()
    }
  ],
  submissions: [],
  payouts: []
};

if (!fs.existsSync(dbPath)) {
  fs.writeFileSync(dbPath, JSON.stringify(seed, null, 2), "utf-8");
}

const readDb = () => JSON.parse(fs.readFileSync(dbPath, "utf-8"));
const writeDb = (db) => fs.writeFileSync(dbPath, JSON.stringify(db, null, 2), "utf-8");
const makeId = (prefix) => `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

const sanitizeUser = (u) => ({
  id: u.id,
  username: u.username,
  role: u.role,
  email: u.email || "",
  city: u.city || "",
  age: u.age || "",
  goal: u.goal || "",
  bio: u.bio || "",
  transport: u.transport || "",
  diet: u.diet || "",
  recycling: u.recycling || "",
  createdAt: u.createdAt || ""
});

const normalizeChallenge = (challenge) => ({
  ...challenge,
  assignedUserIds: Array.isArray(challenge.assignedUserIds) ? challenge.assignedUserIds : []
});

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadsDir),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, `${Date.now()}_${Math.random().toString(36).slice(2, 8)}${ext}`);
  }
});

const upload = multer({ storage });

app.get("/api/health", (_, res) => {
  res.json({ ok: true, env: NODE_ENV });
});

app.post("/api/register", (req, res) => {
  const db = readDb();
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "").trim();

  if (!username || !password) {
    return res.status(400).json({ error: "Заполни логин и пароль" });
  }

  const exists = db.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
  if (exists) {
    return res.status(409).json({ error: "Пользователь уже существует" });
  }

  const user = {
    id: makeId("user"),
    username,
    password,
    role: "user",
    email: String(req.body.email || "").trim(),
    city: String(req.body.city || "").trim(),
    age: String(req.body.age || "").trim(),
    goal: String(req.body.goal || "").trim(),
    bio: String(req.body.bio || "").trim(),
    transport: String(req.body.transport || "").trim(),
    diet: String(req.body.diet || "").trim(),
    recycling: String(req.body.recycling || "").trim(),
    createdAt: new Date().toISOString()
  };

  db.users.push(user);
  writeDb(db);
  res.status(201).json(sanitizeUser(user));
});

app.post("/api/login", (req, res) => {
  const db = readDb();
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "").trim();
  const user = db.users.find((u) => u.username === username && u.password === password);

  if (!user) {
    return res.status(404).json({ error: "Пользователь не найден" });
  }

  res.json(sanitizeUser(user));
});

app.get("/api/users", (_, res) => {
  const db = readDb();
  res.json(db.users.map(sanitizeUser));
});

app.get("/api/users/:id", (req, res) => {
  const user = readDb().users.find((u) => u.id === req.params.id);
  if (!user) {
    return res.status(404).json({ error: "Пользователь не найден" });
  }
  res.json(sanitizeUser(user));
});

app.put("/api/users/:id", (req, res) => {
  const db = readDb();
  const user = db.users.find((u) => u.id === req.params.id);

  if (!user) {
    return res.status(404).json({ error: "Пользователь не найден" });
  }

  ["username", "email", "city", "age", "goal", "bio", "transport", "diet", "recycling"].forEach((field) => {
    if (field in req.body) user[field] = String(req.body[field] ?? "").trim();
  });

  if ("password" in req.body && String(req.body.password || "").trim()) {
    user.password = String(req.body.password).trim();
  }

  writeDb(db);
  res.json(sanitizeUser(user));
});

app.get("/api/challenges", (req, res) => {
  const all = readDb().challenges.map(normalizeChallenge);
  const onlyActive = req.query.active === "1";
  const filtered = onlyActive ? all.filter((c) => c.active) : all;
  res.json(filtered);
});

app.post("/api/challenges", (req, res) => {
  const db = readDb();
  const challenge = normalizeChallenge({
    id: makeId("challenge"),
    title: String(req.body.title || "Новый челлендж").trim(),
    reward: Number(req.body.reward || 100),
    category: String(req.body.category || "Общее").trim(),
    difficulty: String(req.body.difficulty || "Средний").trim(),
    description: String(req.body.description || "").trim(),
    active: req.body.active !== false,
    assignedUserIds: Array.isArray(req.body.assignedUserIds) ? req.body.assignedUserIds : [],
    createdAt: new Date().toISOString()
  });

  db.challenges.unshift(challenge);
  writeDb(db);
  res.status(201).json(challenge);
});

app.put("/api/challenges/:id", (req, res) => {
  const db = readDb();
  const challenge = db.challenges.find((c) => c.id === req.params.id);

  if (!challenge) {
    return res.status(404).json({ error: "Челлендж не найден" });
  }

  ["title", "category", "difficulty", "description"].forEach((field) => {
    if (field in req.body) challenge[field] = String(req.body[field] ?? "").trim();
  });

  if ("reward" in req.body) challenge.reward = Number(req.body.reward || 0);
  if ("active" in req.body) challenge.active = !!req.body.active;
  if ("assignedUserIds" in req.body) {
    challenge.assignedUserIds = Array.isArray(req.body.assignedUserIds) ? req.body.assignedUserIds : [];
  }

  writeDb(db);
  res.json(normalizeChallenge(challenge));
});

app.delete("/api/challenges/:id", (req, res) => {
  const db = readDb();
  const before = db.challenges.length;
  db.challenges = db.challenges.filter((c) => c.id !== req.params.id);

  if (db.challenges.length === before) {
    return res.status(404).json({ error: "Челлендж не найден" });
  }

  writeDb(db);
  res.json({ ok: true });
});

app.get("/api/submissions", (req, res) => {
  const db = readDb();
  let items = db.submissions;
  if (req.query.userId) items = items.filter((s) => s.userId === req.query.userId);
  res.json(items);
});

app.post("/api/submissions", upload.single("photo"), (req, res) => {
  const db = readDb();
  const user = db.users.find((u) => u.id === req.body.userId);
  const challenge = db.challenges
    .map(normalizeChallenge)
    .find((c) => c.id === req.body.challengeId && c.active);

  if (!user) {
    return res.status(400).json({ error: "Пользователь не найден" });
  }

  if (!challenge) {
    return res.status(400).json({ error: "Челлендж не найден или отключен" });
  }

  const assigned = Array.isArray(challenge.assignedUserIds) ? challenge.assignedUserIds : [];
  if (assigned.length > 0 && !assigned.includes(user.id)) {
    return res.status(403).json({ error: "Этот челлендж не назначен данному пользователю" });
  }

  if (!req.file) {
    return res.status(400).json({ error: "Прикрепи фото" });
  }

  const submission = {
    id: makeId("submission"),
    userId: user.id,
    username: user.username,
    challengeId: challenge.id,
    challengeTitle: challenge.title,
    reward: challenge.reward,
    comment: String(req.body.comment || "").trim(),
    photoUrl: `/uploads/${req.file.filename}`,
    status: "pending",
    adminComment: "",
    createdAt: new Date().toISOString()
  };

  db.submissions.unshift(submission);
  writeDb(db);
  res.status(201).json(submission);
});

app.patch("/api/submissions/:id", (req, res) => {
  const db = readDb();
  const submission = db.submissions.find((s) => s.id === req.params.id);

  if (!submission) {
    return res.status(404).json({ error: "Заявка не найдена" });
  }

  if (["pending", "approved", "rejected", "paid"].includes(req.body.status)) {
    submission.status = req.body.status;
  }

  if ("adminComment" in req.body) {
    submission.adminComment = String(req.body.adminComment || "").trim();
  }

  if (submission.status === "paid" && !db.payouts.find((p) => p.submissionId === submission.id)) {
    db.payouts.unshift({
      id: makeId("payout"),
      submissionId: submission.id,
      userId: submission.userId,
      username: submission.username,
      amount: Number(submission.reward || 0),
      createdAt: new Date().toISOString()
    });
  }

  writeDb(db);
  res.json(submission);
});

app.get("/api/payouts", (_, res) => {
  res.json(readDb().payouts);
});

app.get("/api/admin/stats", (_, res) => {
  const db = readDb();
  res.json({
    users: db.users.length,
    challenges: db.challenges.length,
    activeChallenges: db.challenges.filter((c) => c.active).length,
    submissions: db.submissions.length,
    pending: db.submissions.filter((s) => s.status === "pending").length,
    approved: db.submissions.filter((s) => s.status === "approved" || s.status === "paid").length,
    rejected: db.submissions.filter((s) => s.status === "rejected").length,
    payouts: db.payouts.length,
    totalPaid: db.payouts.reduce((sum, p) => sum + Number(p.amount || 0), 0)
  });
});

app.get("/", (_, res) => {
  res.sendFile(path.join(FRONTEND_DIR, "index.html"));
});

app.get("/admin", (_, res) => {
  res.sendFile(path.join(FRONTEND_DIR, "admin.html"));
});

app.get("/user", (_, res) => {
  res.sendFile(path.join(FRONTEND_DIR, "user.html"));
});

app.listen(PORT, () => {
  console.log(`Green Step backend running on http://localhost:${PORT} (${NODE_ENV})`);
});
