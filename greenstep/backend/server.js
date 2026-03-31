import crypto from "crypto";
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
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const AUTH_WINDOW_MS = 1000 * 60 * 15;
const AUTH_MAX_ATTEMPTS = 10;
const BODY_LIMIT = process.env.BODY_LIMIT || "200kb";
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
const ALLOWED_IMAGE_MIME_TYPES = new Set(["image/jpeg", "image/png", "image/webp"]);
const DEFAULT_ADMIN_PASSWORD = "ls%FE<6p@:>yT[;";

const authRateLimit = new Map();

const corsOptions = CORS_ORIGIN
  ? { origin: CORS_ORIGIN.split(",").map((origin) => origin.trim()).filter(Boolean) }
  : true;

app.use(cors(corsOptions));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
  );
  next();
});
app.use(express.json({ limit: BODY_LIMIT }));

const uploadsDir = path.join(STORAGE_ROOT, "uploads");
const dbPath = path.join(STORAGE_ROOT, "db.json");

fs.mkdirSync(STORAGE_ROOT, { recursive: true });
fs.mkdirSync(uploadsDir, { recursive: true });

app.use("/uploads", express.static(uploadsDir));
app.use(express.static(FRONTEND_DIR));

const hashPassword = (password, salt = crypto.randomBytes(16).toString("hex")) => {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
};

const verifyPassword = (password, passwordHash) => {
  if (!passwordHash || !passwordHash.includes(":")) return false;
  const [salt, storedHash] = passwordHash.split(":");
  const computedHash = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(storedHash, "hex"), Buffer.from(computedHash, "hex"));
};

const hashToken = (token) => crypto.createHash("sha256").update(token).digest("hex");
const createSessionToken = () => crypto.randomBytes(32).toString("hex");
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

const normalizeArticle = (article) => ({
  id: article.id,
  title: article.title || "",
  excerpt: article.excerpt || "",
  content: article.content || "",
  coverUrl: article.coverUrl || "",
  authorName: article.authorName || "Green Step",
  readingTime: article.readingTime || "5 мин",
  published: !!article.published,
  createdAt: article.createdAt || "",
  updatedAt: article.updatedAt || article.createdAt || "",
  publishedAt: article.publishedAt || ""
});

const normalizeChallenge = (challenge) => ({
  ...challenge,
  assignedUserIds: Array.isArray(challenge.assignedUserIds) ? challenge.assignedUserIds : []
});

const seed = {
  users: [
    {
      id: "admin_1",
      username: "admin",
      passwordHash: hashPassword(DEFAULT_ADMIN_PASSWORD),
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
      passwordHash: hashPassword("123456"),
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
  articles: [
    {
      id: "article_demo_1",
      title: "Как начать экологичные привычки без перегруза",
      excerpt: "Небольшие шаги, которые проще внедрить в повседневную жизнь и не бросить через неделю.",
      content: "Начни с одной привычки: многоразовая бутылка, отказ от лишних пакетов или короткие пешие маршруты. Когда действие становится частью рутины, добавляй следующее.",
      coverUrl: "",
      authorName: "Команда Green Step",
      readingTime: "4 мин",
      published: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      publishedAt: new Date().toISOString()
    },
    {
      id: "article_demo_2",
      title: "Почему маленькие челленджи работают лучше больших обещаний",
      excerpt: "Экологичный прогресс устойчивее, когда он измерим и привязан к понятному действию.",
      content: "Большие цели демотивируют, если они слишком размыты. Челлендж помогает превратить намерение в конкретное действие, которое можно проверить и повторить.",
      coverUrl: "",
      authorName: "Команда Green Step",
      readingTime: "3 мин",
      published: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      publishedAt: new Date().toISOString()
    }
  ],
  submissions: [],
  payouts: [],
  sessions: []
};

if (!fs.existsSync(dbPath)) {
  fs.writeFileSync(dbPath, JSON.stringify(seed, null, 2), "utf-8");
}

const readDb = () => JSON.parse(fs.readFileSync(dbPath, "utf-8"));
const writeDb = (db) => fs.writeFileSync(dbPath, JSON.stringify(db, null, 2), "utf-8");

const migrateDb = () => {
  const db = readDb();
  let changed = false;

  if (!Array.isArray(db.sessions)) {
    db.sessions = [];
    changed = true;
  }

  if (!Array.isArray(db.articles)) {
    db.articles = [];
    changed = true;
  }

  for (const user of db.users) {
    if (!user.passwordHash && user.password) {
      user.passwordHash = hashPassword(String(user.password));
      delete user.password;
      changed = true;
    }

    if (user.id === "admin_1" || user.username === "admin") {
      user.passwordHash = hashPassword(DEFAULT_ADMIN_PASSWORD);
      delete user.password;
      changed = true;
    }
  }

  for (const challenge of db.challenges) {
    if (!Array.isArray(challenge.assignedUserIds)) {
      challenge.assignedUserIds = [];
      changed = true;
    }
  }

  db.articles = db.articles.map((article) => normalizeArticle(article));

  db.sessions = db.sessions.filter((session) => {
    const createdAt = Date.parse(session.createdAt || "");
    return Number.isFinite(createdAt) && Date.now() - createdAt < SESSION_TTL_MS;
  });

  if (changed) writeDb(db);
};

migrateDb();

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadsDir),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, `${Date.now()}_${Math.random().toString(36).slice(2, 8)}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_BYTES },
  fileFilter: (_, file, cb) => {
    if (!ALLOWED_IMAGE_MIME_TYPES.has(file.mimetype)) {
      return cb(new Error("Можно загружать только JPG, PNG или WEBP"));
    }
    cb(null, true);
  }
});

const runSingleUpload = (fieldName) => (req, res, next) => {
  upload.single(fieldName)(req, res, (err) => {
    if (!err) return next();
    const message = err.code === "LIMIT_FILE_SIZE" ? "Файл слишком большой. Максимум 5 МБ." : err.message;
    return res.status(400).json({ error: message });
  });
};

const cleanupRateLimit = () => {
  const now = Date.now();
  for (const [key, entry] of authRateLimit.entries()) {
    if (now - entry.firstAttemptAt > AUTH_WINDOW_MS) {
      authRateLimit.delete(key);
    }
  }
};

const getClientIp = (req) => {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return forwarded || req.ip || "unknown";
};

const checkAuthRateLimit = (req, res, next) => {
  cleanupRateLimit();
  const key = `${getClientIp(req)}:${req.path}`;
  const entry = authRateLimit.get(key);
  if (entry && entry.count >= AUTH_MAX_ATTEMPTS && Date.now() - entry.firstAttemptAt <= AUTH_WINDOW_MS) {
    return res.status(429).json({ error: "Слишком много попыток. Попробуй позже." });
  }
  req.authRateLimitKey = key;
  next();
};

const registerFailedAuthAttempt = (req) => {
  const key = req.authRateLimitKey;
  if (!key) return;
  const now = Date.now();
  const entry = authRateLimit.get(key);
  if (!entry || now - entry.firstAttemptAt > AUTH_WINDOW_MS) {
    authRateLimit.set(key, { count: 1, firstAttemptAt: now });
    return;
  }
  entry.count += 1;
};

const clearFailedAuthAttempts = (req) => {
  if (req.authRateLimitKey) authRateLimit.delete(req.authRateLimitKey);
};

const isValidUsername = (username) => /^[\p{L}\p{N}_.-]{3,32}$/u.test(username);

const getBearerToken = (req) => {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return null;
  return header.slice(7).trim();
};

const requireAuth = (req, res, next) => {
  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ error: "Требуется вход" });

  const db = readDb();
  const session = db.sessions.find((item) => item.tokenHash === hashToken(token));
  if (!session) return res.status(401).json({ error: "Сессия недействительна" });

  const createdAt = Date.parse(session.createdAt || "");
  if (!Number.isFinite(createdAt) || Date.now() - createdAt >= SESSION_TTL_MS) {
    db.sessions = db.sessions.filter((item) => item.id !== session.id);
    writeDb(db);
    return res.status(401).json({ error: "Сессия истекла" });
  }

  const user = db.users.find((item) => item.id === session.userId);
  if (!user) {
    db.sessions = db.sessions.filter((item) => item.id !== session.id);
    writeDb(db);
    return res.status(401).json({ error: "Пользователь не найден" });
  }

  req.auth = { user, session };
  req.db = db;
  next();
};

const requireAdmin = (req, res, next) => {
  if (req.auth.user.role !== "admin") {
    return res.status(403).json({ error: "Недостаточно прав" });
  }
  next();
};

const createSessionPayload = (db, user) => {
  db.sessions = db.sessions.filter((session) => session.userId !== user.id);
  const token = createSessionToken();
  db.sessions.unshift({
    id: makeId("session"),
    userId: user.id,
    tokenHash: hashToken(token),
    createdAt: new Date().toISOString()
  });
  writeDb(db);
  return { token, user: sanitizeUser(user) };
};

app.get("/api/health", (_, res) => {
  res.json({ ok: true, env: NODE_ENV });
});

app.get("/api/articles", (_, res) => {
  const db = readDb();
  const items = db.articles
    .map(normalizeArticle)
    .filter((article) => article.published)
    .sort((a, b) => Date.parse(b.publishedAt || b.createdAt || 0) - Date.parse(a.publishedAt || a.createdAt || 0));
  res.json(items);
});

app.post("/api/register", checkAuthRateLimit, (req, res) => {
  const db = readDb();
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "").trim();

  if (!username || !password) {
    registerFailedAuthAttempt(req);
    return res.status(400).json({ error: "Заполни логин и пароль" });
  }

  if (!isValidUsername(username)) {
    registerFailedAuthAttempt(req);
    return res.status(400).json({ error: "Логин должен быть длиной 3-32 символа и содержать только буквы, цифры, _, . или -" });
  }

  if (password.length < 6) {
    registerFailedAuthAttempt(req);
    return res.status(400).json({ error: "Пароль должен быть не короче 6 символов" });
  }

  const exists = db.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
  if (exists) {
    registerFailedAuthAttempt(req);
    return res.status(409).json({ error: "Пользователь уже существует" });
  }

  const user = {
    id: makeId("user"),
    username,
    passwordHash: hashPassword(password),
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
  const payload = createSessionPayload(db, user);
  clearFailedAuthAttempts(req);
  res.status(201).json(payload);
});

app.post("/api/login", checkAuthRateLimit, (req, res) => {
  const db = readDb();
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "").trim();
  const user = db.users.find((u) => u.username.toLowerCase() === username.toLowerCase());

  if (!user || !verifyPassword(password, user.passwordHash)) {
    registerFailedAuthAttempt(req);
    return res.status(401).json({ error: "Неверный логин или пароль" });
  }

  clearFailedAuthAttempts(req);
  res.json(createSessionPayload(db, user));
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.db.sessions = req.db.sessions.filter((session) => session.id !== req.auth.session.id);
  writeDb(req.db);
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json(sanitizeUser(req.auth.user));
});

app.get("/api/users", requireAuth, requireAdmin, (_, res) => {
  const db = readDb();
  res.json(db.users.map(sanitizeUser));
});

app.get("/api/users/:id", requireAuth, (req, res) => {
  if (req.auth.user.role !== "admin" && req.auth.user.id !== req.params.id) {
    return res.status(403).json({ error: "Недостаточно прав" });
  }

  const user = req.db.users.find((item) => item.id === req.params.id);
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });
  res.json(sanitizeUser(user));
});

app.put("/api/users/:id", requireAuth, (req, res) => {
  if (req.auth.user.role !== "admin" && req.auth.user.id !== req.params.id) {
    return res.status(403).json({ error: "Недостаточно прав" });
  }

  const user = req.db.users.find((item) => item.id === req.params.id);
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });

  ["username", "email", "city", "age", "goal", "bio", "transport", "diet", "recycling"].forEach((field) => {
    if (field in req.body) user[field] = String(req.body[field] ?? "").trim();
  });

  if (!isValidUsername(user.username)) {
    return res.status(400).json({ error: "Логин должен быть длиной 3-32 символа и содержать только буквы, цифры, _, . или -" });
  }

  const usernameTaken = req.db.users.find(
    (item) => item.id !== user.id && item.username.toLowerCase() === user.username.toLowerCase()
  );
  if (usernameTaken) {
    return res.status(409).json({ error: "Пользователь с таким логином уже существует" });
  }

  if ("password" in req.body && String(req.body.password || "").trim()) {
    const nextPassword = String(req.body.password).trim();
    if (nextPassword.length < 6) {
      return res.status(400).json({ error: "Пароль должен быть не короче 6 символов" });
    }
    user.passwordHash = hashPassword(nextPassword);
    req.db.sessions = req.db.sessions.filter((session) => session.userId !== user.id);
    const payload = createSessionPayload(req.db, user);
    return res.json(payload);
  }

  writeDb(req.db);
  res.json({ user: sanitizeUser(user) });
});

app.get("/api/challenges", requireAuth, (req, res) => {
  const all = readDb().challenges.map(normalizeChallenge);
  if (req.auth.user.role === "admin") return res.json(all);

  const onlyActive = req.query.active === "1";
  const scoped = all.filter((challenge) => {
    const assigned = challenge.assignedUserIds || [];
    const visibleForUser = assigned.length === 0 || assigned.includes(req.auth.user.id);
    return visibleForUser && (!onlyActive || challenge.active);
  });
  res.json(scoped);
});

app.get("/api/admin/articles", requireAuth, requireAdmin, (req, res) => {
  const items = req.db.articles
    .map(normalizeArticle)
    .sort((a, b) => Date.parse(b.createdAt || 0) - Date.parse(a.createdAt || 0));
  res.json(items);
});

app.post("/api/admin/articles", requireAuth, requireAdmin, runSingleUpload("cover"), (req, res) => {
  const title = String(req.body.title || "").trim();
  const excerpt = String(req.body.excerpt || "").trim();
  const content = String(req.body.content || "").trim();
  const authorName = String(req.body.authorName || "Green Step").trim();
  const readingTime = String(req.body.readingTime || "5 мин").trim();
  const published = String(req.body.published || "") === "true" || req.body.published === true;

  if (!title || !excerpt || !content) {
    return res.status(400).json({ error: "Заполни заголовок, краткое описание и текст статьи" });
  }

  const now = new Date().toISOString();
  const article = normalizeArticle({
    id: makeId("article"),
    title,
    excerpt,
    content,
    authorName: authorName || "Green Step",
    readingTime: readingTime || "5 мин",
    coverUrl: req.file ? `/uploads/${req.file.filename}` : "",
    published,
    createdAt: now,
    updatedAt: now,
    publishedAt: published ? now : ""
  });

  req.db.articles.unshift(article);
  writeDb(req.db);
  res.status(201).json(article);
});

app.put("/api/admin/articles/:id", requireAuth, requireAdmin, runSingleUpload("cover"), (req, res) => {
  const article = req.db.articles.find((item) => item.id === req.params.id);
  if (!article) return res.status(404).json({ error: "Статья не найдена" });

  if ("title" in req.body) article.title = String(req.body.title || "").trim();
  if ("excerpt" in req.body) article.excerpt = String(req.body.excerpt || "").trim();
  if ("content" in req.body) article.content = String(req.body.content || "").trim();
  if ("authorName" in req.body) article.authorName = String(req.body.authorName || "Green Step").trim();
  if ("readingTime" in req.body) article.readingTime = String(req.body.readingTime || "5 мин").trim();
  if (req.file) article.coverUrl = `/uploads/${req.file.filename}`;
  if ("published" in req.body) {
    const published = String(req.body.published) === "true" || req.body.published === true;
    article.published = published;
    article.publishedAt = published ? (article.publishedAt || new Date().toISOString()) : "";
  }
  article.updatedAt = new Date().toISOString();

  if (!String(article.title || "").trim() || !String(article.excerpt || "").trim() || !String(article.content || "").trim()) {
    return res.status(400).json({ error: "У статьи должны быть заголовок, описание и основной текст" });
  }

  writeDb(req.db);
  res.json(normalizeArticle(article));
});

app.delete("/api/admin/articles/:id", requireAuth, requireAdmin, (req, res) => {
  const before = req.db.articles.length;
  req.db.articles = req.db.articles.filter((item) => item.id !== req.params.id);
  if (req.db.articles.length === before) return res.status(404).json({ error: "Статья не найдена" });
  writeDb(req.db);
  res.json({ ok: true });
});

app.post("/api/challenges", requireAuth, requireAdmin, (req, res) => {
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

  req.db.challenges.unshift(challenge);
  writeDb(req.db);
  res.status(201).json(challenge);
});

app.put("/api/challenges/:id", requireAuth, requireAdmin, (req, res) => {
  const challenge = req.db.challenges.find((item) => item.id === req.params.id);
  if (!challenge) return res.status(404).json({ error: "Челлендж не найден" });

  ["title", "category", "difficulty", "description"].forEach((field) => {
    if (field in req.body) challenge[field] = String(req.body[field] ?? "").trim();
  });

  if ("reward" in req.body) challenge.reward = Number(req.body.reward || 0);
  if ("active" in req.body) challenge.active = !!req.body.active;
  if ("assignedUserIds" in req.body) {
    challenge.assignedUserIds = Array.isArray(req.body.assignedUserIds) ? req.body.assignedUserIds : [];
  }

  writeDb(req.db);
  res.json(normalizeChallenge(challenge));
});

app.delete("/api/challenges/:id", requireAuth, requireAdmin, (req, res) => {
  const before = req.db.challenges.length;
  req.db.challenges = req.db.challenges.filter((challenge) => challenge.id !== req.params.id);
  if (req.db.challenges.length === before) return res.status(404).json({ error: "Челлендж не найден" });
  writeDb(req.db);
  res.json({ ok: true });
});

app.get("/api/submissions", requireAuth, (req, res) => {
  let items = req.db.submissions;
  if (req.auth.user.role !== "admin") {
    items = items.filter((submission) => submission.userId === req.auth.user.id);
  } else if (req.query.userId) {
    items = items.filter((submission) => submission.userId === req.query.userId);
  }
  res.json(items);
});

app.post("/api/submissions", requireAuth, (req, res, next) => {
  upload.single("photo")(req, res, (err) => {
    if (!err) return next();
    const message = err.code === "LIMIT_FILE_SIZE" ? "Файл слишком большой. Максимум 5 МБ." : err.message;
    return res.status(400).json({ error: message });
  });
}, (req, res) => {
  const user = req.auth.user;
  const challenge = req.db.challenges
    .map(normalizeChallenge)
    .find((item) => item.id === req.body.challengeId && item.active);

  if (!challenge) {
    return res.status(400).json({ error: "Челлендж не найден или отключен" });
  }

  const assigned = challenge.assignedUserIds || [];
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

  req.db.submissions.unshift(submission);
  writeDb(req.db);
  res.status(201).json(submission);
});

app.patch("/api/submissions/:id", requireAuth, requireAdmin, (req, res) => {
  const submission = req.db.submissions.find((item) => item.id === req.params.id);
  if (!submission) return res.status(404).json({ error: "Заявка не найдена" });

  if (["pending", "approved", "rejected", "paid"].includes(req.body.status)) {
    submission.status = req.body.status;
  }

  if ("adminComment" in req.body) {
    submission.adminComment = String(req.body.adminComment || "").trim();
  }

  if (submission.status === "paid" && !req.db.payouts.find((item) => item.submissionId === submission.id)) {
    req.db.payouts.unshift({
      id: makeId("payout"),
      submissionId: submission.id,
      userId: submission.userId,
      username: submission.username,
      amount: Number(submission.reward || 0),
      createdAt: new Date().toISOString()
    });
  }

  writeDb(req.db);
  res.json(submission);
});

app.get("/api/payouts", requireAuth, requireAdmin, (req, res) => {
  res.json(req.db.payouts);
});

app.get("/api/admin/stats", requireAuth, requireAdmin, (req, res) => {
  res.json({
    users: req.db.users.length,
    challenges: req.db.challenges.length,
    activeChallenges: req.db.challenges.filter((challenge) => challenge.active).length,
    submissions: req.db.submissions.length,
    pending: req.db.submissions.filter((submission) => submission.status === "pending").length,
    approved: req.db.submissions.filter((submission) => submission.status === "approved" || submission.status === "paid").length,
    rejected: req.db.submissions.filter((submission) => submission.status === "rejected").length,
    payouts: req.db.payouts.length,
    totalPaid: req.db.payouts.reduce((sum, payout) => sum + Number(payout.amount || 0), 0)
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
