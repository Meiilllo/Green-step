import crypto from "crypto";
import express from "express";
import cors from "cors";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import { initDatabase, query, withTransaction } from "./db.js";

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
const TELEGRAM_BOT_TOKEN = String(process.env.TELEGRAM_BOT_TOKEN || "").trim();
const TELEGRAM_CHANNEL_ID = String(process.env.TELEGRAM_CHANNEL_ID || "").trim();
const TELEGRAM_WEBHOOK_SECRET = String(process.env.TELEGRAM_WEBHOOK_SECRET || "").trim();
const SITE_URL = String(process.env.SITE_URL || "").trim().replace(/\/+$/, "");
const TELEGRAM_ADMIN_IDS = new Set(
  String(process.env.TELEGRAM_ADMIN_IDS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
);
const TELEGRAM_API_BASE = TELEGRAM_BOT_TOKEN ? `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}` : "";
const TELEGRAM_WEBHOOK_PATH = TELEGRAM_WEBHOOK_SECRET
  ? `/api/telegram/webhook/${TELEGRAM_WEBHOOK_SECRET}`
  : "/api/telegram/webhook";
const TELEGRAM_WEBHOOK_URL = SITE_URL ? `${SITE_URL}${TELEGRAM_WEBHOOK_PATH}` : "";
const TELEGRAM_ENABLED = Boolean(TELEGRAM_BOT_TOKEN);

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
    "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
  );
  next();
});
app.use(express.json({ limit: BODY_LIMIT }));

const uploadsDir = path.join(STORAGE_ROOT, "uploads");
const legacyDataPath = path.join(__dirname, "data", "db.json");
const legacyStorageDbPath = path.join(STORAGE_ROOT, "db.json");

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
const isValidUsername = (username) => /^[\p{L}\p{N}_.-]{3,32}$/u.test(username);

const toIsoString = (value) => {
  if (!value) return "";
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
};

const sanitizeUser = (user) => ({
  id: user.id,
  username: user.username,
  role: user.role,
  email: user.email || "",
  city: user.city || "",
  age: user.age || "",
  goal: user.goal || "",
  bio: user.bio || "",
  transport: user.transport || "",
  diet: user.diet || "",
  recycling: user.recycling || "",
  createdAt: toIsoString(user.created_at || user.createdAt)
});

const normalizeArticle = (article) => ({
  id: article.id,
  title: article.title || "",
  excerpt: article.excerpt || "",
  content: article.content || "",
  coverUrl: article.cover_url || article.coverUrl || "",
  authorName: article.author_name || article.authorName || "Green Step",
  readingTime: article.reading_time || article.readingTime || "5 мин",
  published: !!article.published,
  createdAt: toIsoString(article.created_at || article.createdAt),
  updatedAt: toIsoString(article.updated_at || article.updatedAt || article.created_at || article.createdAt),
  publishedAt: toIsoString(article.published_at || article.publishedAt)
});

const normalizeChallenge = (challenge) => ({
  id: challenge.id,
  title: challenge.title || "",
  reward: Number(challenge.reward || 0),
  category: challenge.category || "",
  difficulty: challenge.difficulty || "",
  description: challenge.description || "",
  active: !!challenge.active,
  assignedUserIds: Array.isArray(challenge.assigned_user_ids)
    ? challenge.assigned_user_ids
    : Array.isArray(challenge.assignedUserIds)
      ? challenge.assignedUserIds
      : [],
  createdAt: toIsoString(challenge.created_at || challenge.createdAt)
});

const normalizeSubmission = (submission) => ({
  id: submission.id,
  userId: submission.user_id || submission.userId,
  username: submission.username || "",
  challengeId: submission.challenge_id || submission.challengeId,
  challengeTitle: submission.challenge_title || submission.challengeTitle || "",
  reward: Number(submission.reward || 0),
  comment: submission.comment || "",
  photoUrl: submission.photo_url || submission.photoUrl || "",
  status: submission.status || "pending",
  adminComment: submission.admin_comment || submission.adminComment || "",
  createdAt: toIsoString(submission.created_at || submission.createdAt)
});

const normalizePayout = (payout) => ({
  id: payout.id,
  submissionId: payout.submission_id || payout.submissionId,
  userId: payout.user_id || payout.userId,
  username: payout.username || "",
  amount: Number(payout.amount || 0),
  createdAt: toIsoString(payout.created_at || payout.createdAt)
});

const BOT_STATE_IDLE = "idle";
const BOT_STATE_AWAITING_TITLE = "awaiting_title";
const BOT_STATE_AWAITING_EXCERPT = "awaiting_excerpt";
const BOT_STATE_AWAITING_CONTENT = "awaiting_content";
const BOT_STATE_AWAITING_COVER = "awaiting_cover";
const BOT_STATE_AWAITING_PUBLISH_MODE = "awaiting_publish_mode";
const BOT_STATE_AWAITING_CONFIRM = "awaiting_confirm";
const BOT_ACTION_CREATE_DRAFT = "create_draft";
const BOT_ACTION_CREATE_AND_PUBLISH = "create_and_publish";
const BOT_POST_MODE_TITLE = "title";
const BOT_POST_MODE_EXCERPT = "excerpt";
const BOT_POST_MODE_FULL = "full";

const escapeTelegramHtml = (value) => String(value || "")
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;");

const getTelegramUserFromUpdate = (update) => (
  update?.message?.from
  || update?.callback_query?.from
  || update?.edited_message?.from
  || null
);

const getTelegramChatIdFromUpdate = (update) => (
  update?.message?.chat?.id
  || update?.callback_query?.message?.chat?.id
  || update?.edited_message?.chat?.id
  || null
);

const isTelegramAdmin = (user) => {
  if (!user?.id) return false;
  return TELEGRAM_ADMIN_IDS.has(String(user.id));
};

const telegramMenuKeyboard = {
  keyboard: [
    [{ text: "Создать статью" }, { text: "Создать и опубликовать" }],
    [{ text: "Черновики" }, { text: "Помощь" }]
  ],
  resize_keyboard: true
};

const telegramCoverKeyboard = {
  keyboard: [
    [{ text: "Пропустить" }],
    [{ text: "Отмена" }]
  ],
  resize_keyboard: true
};

const telegramPublishModeKeyboard = {
  keyboard: [
    [{ text: "Название статьи" }],
    [{ text: "Краткий текст" }],
    [{ text: "Полный текст" }],
    [{ text: "Отмена" }]
  ],
  resize_keyboard: true
};

const telegramDraftConfirmKeyboard = {
  keyboard: [
    [{ text: "Сохранить как черновик" }],
    [{ text: "Отмена" }]
  ],
  resize_keyboard: true
};

const telegramPublishConfirmKeyboard = {
  keyboard: [
    [{ text: "Опубликовать" }],
    [{ text: "Сохранить как черновик" }],
    [{ text: "Отмена" }]
  ],
  resize_keyboard: true
};

const telegramRequest = async (method, payload = {}) => {
  if (!TELEGRAM_ENABLED) {
    throw new Error("Telegram bot is not configured");
  }

  const response = await fetch(`${TELEGRAM_API_BASE}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok || data?.ok === false) {
    throw new Error(data?.description || `Telegram API request failed: ${method}`);
  }

  return data;
};

const sendTelegramMessage = (chatId, text, extra = {}) => telegramRequest("sendMessage", {
  chat_id: chatId,
  text,
  parse_mode: "HTML",
  ...extra
});

const getTelegramSession = async (telegramUserId) => {
  const { rows } = await query(
    "SELECT * FROM bot_sessions WHERE telegram_user_id = $1 LIMIT 1",
    [String(telegramUserId)]
  );
  return rows[0] || null;
};

const setTelegramSession = async (telegramUserId, state, payload = {}) => {
  const now = new Date().toISOString();
  const { rows } = await query(
    `INSERT INTO bot_sessions (id, telegram_user_id, state, payload_json, created_at, updated_at)
    VALUES ($1, $2, $3, $4::jsonb, $5, $5)
    ON CONFLICT (telegram_user_id)
    DO UPDATE SET state = EXCLUDED.state, payload_json = EXCLUDED.payload_json, updated_at = EXCLUDED.updated_at
    RETURNING *`,
    [makeId("bot_session"), String(telegramUserId), state, JSON.stringify(payload || {}), now]
  );
  return rows[0];
};

const clearTelegramSession = async (telegramUserId) => {
  await query("DELETE FROM bot_sessions WHERE telegram_user_id = $1", [String(telegramUserId)]);
};

const articleUrl = (articleId) => SITE_URL ? `${SITE_URL}/article?id=${encodeURIComponent(articleId)}` : "";

const createArticleRecord = async ({
  title,
  excerpt,
  content,
  coverUrl = "",
  authorName = "Green Step",
  readingTime = "5 мин",
  published = false
}) => {
  const now = new Date().toISOString();
  const { rows } = await query(
    `INSERT INTO articles (
      id, title, excerpt, content, cover_url, author_name, reading_time, published, created_at, updated_at, published_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    RETURNING *`,
    [
      makeId("article"),
      title,
      excerpt,
      content,
      coverUrl,
      authorName,
      readingTime,
      published,
      now,
      now,
      published ? now : null
    ]
  );
  return normalizeArticle(rows[0]);
};

const buildTelegramArticlePreview = (payload) => {
  const lines = [
    "<b>Предпросмотр статьи</b>",
    "",
    `<b>Название:</b> ${escapeTelegramHtml(payload.title)}`,
    "",
    `<b>Краткий текст:</b>\n${escapeTelegramHtml(payload.excerpt)}`,
    "",
    `<b>Полный текст:</b>\n${escapeTelegramHtml(payload.content.length > 800 ? `${payload.content.slice(0, 800)}...` : payload.content)}`
  ];

  if (payload.coverUrl) {
    lines.push("", "<b>Картинка:</b> добавлена");
  }

  if (payload.publishMode) {
    const modeLabel = payload.publishMode === BOT_POST_MODE_TITLE
      ? "Название статьи"
      : payload.publishMode === BOT_POST_MODE_EXCERPT
        ? "Краткий текст"
        : "Полный текст";
    lines.push("", `<b>Режим публикации в канал:</b> ${modeLabel}`);
  }

  return lines.join("\n");
};

const getTelegramPublishText = (article, publishMode) => {
  const header = `<b>${escapeTelegramHtml(article.title)}</b>`;
  const body = publishMode === BOT_POST_MODE_TITLE
    ? ""
    : publishMode === BOT_POST_MODE_EXCERPT
      ? escapeTelegramHtml(article.excerpt || "")
      : escapeTelegramHtml(article.content || "");
  const link = articleUrl(article.id);

  return [
    header,
    body ? `\n${body}` : "",
    link ? `\n<a href="${escapeTelegramHtml(link)}">Читать на сайте</a>` : ""
  ].join("\n").trim();
};

const publishArticleToTelegramChannel = async (article, publishMode) => {
  if (!TELEGRAM_CHANNEL_ID) {
    throw new Error("TELEGRAM_CHANNEL_ID is not configured");
  }

  const text = getTelegramPublishText(article, publishMode);
  const replyMarkup = articleUrl(article.id)
    ? {
        inline_keyboard: [[{ text: "Открыть статью", url: articleUrl(article.id) }]]
      }
    : undefined;

  if (article.coverUrl && SITE_URL) {
    const photoUrl = `${SITE_URL}${article.coverUrl}`;
    return telegramRequest("sendPhoto", {
      chat_id: TELEGRAM_CHANNEL_ID,
      photo: photoUrl,
      caption: text.slice(0, 1024),
      parse_mode: "HTML",
      reply_markup: replyMarkup
    });
  }

  return sendTelegramMessage(TELEGRAM_CHANNEL_ID, text, { reply_markup: replyMarkup });
};

const downloadTelegramFile = async (fileId) => {
  const fileMeta = await telegramRequest("getFile", { file_id: fileId });
  const filePath = fileMeta?.result?.file_path;
  if (!filePath) {
    throw new Error("Telegram did not return a file path");
  }

  const fileUrl = `https://api.telegram.org/file/bot${TELEGRAM_BOT_TOKEN}/${filePath}`;
  const response = await fetch(fileUrl);
  if (!response.ok) {
    throw new Error("Failed to download Telegram file");
  }

  const buffer = Buffer.from(await response.arrayBuffer());
  const ext = path.extname(filePath) || ".jpg";
  const filename = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}${ext}`;
  const targetPath = path.join(uploadsDir, filename);
  fs.writeFileSync(targetPath, buffer);
  return `/uploads/${filename}`;
};

const startTelegramArticleFlow = async (chatId, telegramUserId, action) => {
  await setTelegramSession(telegramUserId, BOT_STATE_AWAITING_TITLE, { action });
  await sendTelegramMessage(
    chatId,
    "Отправь название статьи.",
    { reply_markup: { keyboard: [[{ text: "Отмена" }]], resize_keyboard: true } }
  );
};

const setupTelegramWebhook = async () => {
  if (!TELEGRAM_ENABLED) {
    console.log("Telegram bot is disabled: TELEGRAM_BOT_TOKEN is not set");
    return;
  }

  if (!SITE_URL) {
    console.log("Telegram bot is configured, but webhook setup is skipped because SITE_URL is missing");
    return;
  }

  await telegramRequest("setWebhook", {
    url: TELEGRAM_WEBHOOK_URL,
    secret_token: TELEGRAM_WEBHOOK_SECRET || undefined,
    allowed_updates: ["message", "callback_query"]
  });

  console.log(`Telegram webhook configured at ${TELEGRAM_WEBHOOK_URL}`);
};

const handleTelegramStart = async (chatId, user) => {
  const name = escapeTelegramHtml(user?.first_name || user?.username || "админ");
  await clearTelegramSession(user.id);
  await sendTelegramMessage(
    chatId,
    [
      `Привет, <b>${name}</b>.`,
      "",
      "Бот Green Step подключен.",
      "На этом этапе уже работают webhook, проверка админов и базовое меню.",
      "",
      "Следующим шагом добавим создание статей, загрузку картинок и публикацию в канал."
    ].join("\n"),
    { reply_markup: telegramMenuKeyboard }
  );
};

const handleTelegramPlaceholderAction = async (chatId, text) => {
  const safeText = escapeTelegramHtml(text);
  await sendTelegramMessage(
    chatId,
    `Пункт <b>${safeText}</b> уже подключён в меню. На следующем этапе добавлю для него реальный сценарий.`
  );
};

const handleTelegramHelp = async (chatId) => {
  await sendTelegramMessage(
    chatId,
    [
      "<b>Что уже умеет бот</b>",
      "",
      "1. Создавать черновики статей.",
      "2. Создавать статью и публиковать её в канал.",
      "3. Принимать картинку для статьи.",
      "4. Публиковать в канал в одном из режимов: название, краткий текст, полный текст."
    ].join("\n"),
    { reply_markup: telegramMenuKeyboard }
  );
};

const handleTelegramDrafts = async (chatId) => {
  const { rows } = await query(
    `SELECT * FROM articles
    WHERE published = FALSE
    ORDER BY created_at DESC
    LIMIT 5`
  );

  if (!rows.length) {
    await sendTelegramMessage(chatId, "Черновиков пока нет.", { reply_markup: telegramMenuKeyboard });
    return;
  }

  const text = rows.map((row, index) => `${index + 1}. ${escapeTelegramHtml(row.title || "Без названия")}`).join("\n");
  await sendTelegramMessage(chatId, `<b>Последние черновики</b>\n\n${text}`, { reply_markup: telegramMenuKeyboard });
};

const handleTelegramCancel = async (chatId, telegramUserId) => {
  await clearTelegramSession(telegramUserId);
  await sendTelegramMessage(chatId, "Сценарий отменён.", { reply_markup: telegramMenuKeyboard });
};

const getTelegramPhotoFileId = (message) => {
  const photos = Array.isArray(message?.photo) ? message.photo : [];
  if (!photos.length) return "";
  return photos[photos.length - 1]?.file_id || "";
};

const buildTelegramConfirmKeyboard = (action) => (
  action === BOT_ACTION_CREATE_AND_PUBLISH ? telegramPublishConfirmKeyboard : telegramDraftConfirmKeyboard
);

const handleTelegramSessionStep = async (chatId, user, session, update) => {
  const text = String(update?.message?.text || "").trim();
  const photoFileId = getTelegramPhotoFileId(update?.message);
  const payload = session.payload_json || {};

  if (text === "Отмена") {
    await handleTelegramCancel(chatId, user.id);
    return;
  }

  if (session.state === BOT_STATE_AWAITING_TITLE) {
    if (!text) {
      await sendTelegramMessage(chatId, "Пришли текстом название статьи.");
      return;
    }
    await setTelegramSession(user.id, BOT_STATE_AWAITING_EXCERPT, { ...payload, title: text });
    await sendTelegramMessage(chatId, "Теперь пришли краткий текст статьи.");
    return;
  }

  if (session.state === BOT_STATE_AWAITING_EXCERPT) {
    if (!text) {
      await sendTelegramMessage(chatId, "Пришли текстом краткий текст статьи.");
      return;
    }
    await setTelegramSession(user.id, BOT_STATE_AWAITING_CONTENT, { ...payload, excerpt: text });
    await sendTelegramMessage(chatId, "Теперь пришли полный текст статьи.");
    return;
  }

  if (session.state === BOT_STATE_AWAITING_CONTENT) {
    if (!text) {
      await sendTelegramMessage(chatId, "Пришли текстом полный текст статьи.");
      return;
    }
    await setTelegramSession(user.id, BOT_STATE_AWAITING_COVER, { ...payload, content: text });
    await sendTelegramMessage(
      chatId,
      "Если хочешь, пришли картинку для статьи. Или нажми «Пропустить».",
      { reply_markup: telegramCoverKeyboard }
    );
    return;
  }

  if (session.state === BOT_STATE_AWAITING_COVER) {
    if (text === "Пропустить") {
      await setTelegramSession(user.id, BOT_STATE_AWAITING_PUBLISH_MODE, { ...payload, coverUrl: "" });
      await sendTelegramMessage(chatId, "Выбери, какой текст отправлять в канал.", { reply_markup: telegramPublishModeKeyboard });
      return;
    }

    if (!photoFileId) {
      await sendTelegramMessage(chatId, "Жду картинку или кнопку «Пропустить».", { reply_markup: telegramCoverKeyboard });
      return;
    }

    const coverUrl = await downloadTelegramFile(photoFileId);
    await setTelegramSession(user.id, BOT_STATE_AWAITING_PUBLISH_MODE, { ...payload, coverUrl });
    await sendTelegramMessage(chatId, "Картинка сохранена. Теперь выбери режим публикации.", { reply_markup: telegramPublishModeKeyboard });
    return;
  }

  if (session.state === BOT_STATE_AWAITING_PUBLISH_MODE) {
    let publishMode = "";
    if (text === "Название статьи") publishMode = BOT_POST_MODE_TITLE;
    if (text === "Краткий текст") publishMode = BOT_POST_MODE_EXCERPT;
    if (text === "Полный текст") publishMode = BOT_POST_MODE_FULL;

    if (!publishMode) {
      await sendTelegramMessage(chatId, "Выбери один из вариантов: название, краткий текст или полный текст.", { reply_markup: telegramPublishModeKeyboard });
      return;
    }

    const nextPayload = { ...payload, publishMode };
    await setTelegramSession(user.id, BOT_STATE_AWAITING_CONFIRM, nextPayload);
    await sendTelegramMessage(
      chatId,
      buildTelegramArticlePreview(nextPayload),
      { reply_markup: buildTelegramConfirmKeyboard(payload.action) }
    );
    return;
  }

  if (session.state === BOT_STATE_AWAITING_CONFIRM) {
    if (text !== "Опубликовать" && text !== "Сохранить как черновик") {
      await sendTelegramMessage(
        chatId,
        "Нажми «Опубликовать», «Сохранить как черновик» или «Отмена».",
        { reply_markup: buildTelegramConfirmKeyboard(payload.action) }
      );
      return;
    }

    const shouldPublish = text === "Опубликовать" && payload.action === BOT_ACTION_CREATE_AND_PUBLISH;
    const article = await createArticleRecord({
      title: payload.title,
      excerpt: payload.excerpt,
      content: payload.content,
      coverUrl: payload.coverUrl || "",
      published: shouldPublish
    });

    if (shouldPublish) {
      await publishArticleToTelegramChannel(article, payload.publishMode || BOT_POST_MODE_EXCERPT);
      await clearTelegramSession(user.id);
      await sendTelegramMessage(
        chatId,
        [
          "Статья опубликована на сайте и отправлена в канал.",
          articleUrl(article.id) ? `Ссылка: ${escapeTelegramHtml(articleUrl(article.id))}` : ""
        ].filter(Boolean).join("\n"),
        { reply_markup: telegramMenuKeyboard }
      );
      return;
    }

    await clearTelegramSession(user.id);
    await sendTelegramMessage(
      chatId,
      [
        "Статья сохранена как черновик.",
        articleUrl(article.id) ? `Ссылка: ${escapeTelegramHtml(articleUrl(article.id))}` : ""
      ].filter(Boolean).join("\n"),
      { reply_markup: telegramMenuKeyboard }
    );
  }
};

const handleTelegramUpdate = async (update) => {
  const user = getTelegramUserFromUpdate(update);
  const chatId = getTelegramChatIdFromUpdate(update);
  if (!chatId || !user) return;

  if (!isTelegramAdmin(user)) {
    await sendTelegramMessage(chatId, "Доступ запрещён. Этот бот доступен только администраторам Green Step.");
    return;
  }

  const text = String(update?.message?.text || "").trim();
  const session = await getTelegramSession(user.id);
  if (text === "/start") {
    await handleTelegramStart(chatId, user);
    return;
  }

  if (text === "Создать статью") {
    await startTelegramArticleFlow(chatId, user.id, BOT_ACTION_CREATE_DRAFT);
    return;
  }

  if (text === "Создать и опубликовать") {
    await startTelegramArticleFlow(chatId, user.id, BOT_ACTION_CREATE_AND_PUBLISH);
    return;
  }

  if (text === "Черновики") {
    await handleTelegramDrafts(chatId);
    return;
  }

  if (text === "Помощь") {
    await handleTelegramHelp(chatId);
    return;
  }

  if (text === "Отмена") {
    await handleTelegramCancel(chatId, user.id);
    return;
  }

  if (session) {
    await handleTelegramSessionStep(chatId, user, session, update);
    return;
  }

  if (text) {
    await sendTelegramMessage(
      chatId,
      "Команда получена. Пока доступны /start и базовое меню. Дальше подключим сценарии создания статьи и публикации."
    );
  }
};

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

const asyncHandler = (handler) => (req, res, next) => {
  Promise.resolve(handler(req, res, next)).catch(next);
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

const getBearerToken = (req) => {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return null;
  return header.slice(7).trim();
};

const requireAuth = asyncHandler(async (req, res, next) => {
  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ error: "Требуется вход" });

  const { rows } = await query(
    `SELECT
      s.id AS session_id,
      s.user_id AS session_user_id,
      s.created_at AS session_created_at,
      u.id,
      u.username,
      u.password_hash,
      u.role,
      u.email,
      u.city,
      u.age,
      u.goal,
      u.bio,
      u.transport,
      u.diet,
      u.recycling,
      u.created_at
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = $1
    LIMIT 1`,
    [hashToken(token)]
  );

  const row = rows[0];
  if (!row) return res.status(401).json({ error: "Сессия недействительна" });

  const createdAt = Date.parse(row.session_created_at || "");
  if (!Number.isFinite(createdAt) || Date.now() - createdAt >= SESSION_TTL_MS) {
    await query("DELETE FROM sessions WHERE id = $1", [row.session_id]);
    return res.status(401).json({ error: "Сессия истекла" });
  }

  req.auth = {
    user: sanitizeUser(row),
    userRow: row,
    session: {
      id: row.session_id,
      userId: row.session_user_id,
      createdAt: toIsoString(row.session_created_at)
    }
  };
  next();
});

const requireAdmin = (req, res, next) => {
  if (req.auth.user.role !== "admin") {
    return res.status(403).json({ error: "Недостаточно прав" });
  }
  next();
};

const createSessionPayload = async (userRow) => {
  const token = createSessionToken();
  await withTransaction(async (client) => {
    await client.query("DELETE FROM sessions WHERE user_id = $1", [userRow.id]);
    await client.query(
      "INSERT INTO sessions (id, user_id, token_hash, created_at) VALUES ($1, $2, $3, $4)",
      [makeId("session"), userRow.id, hashToken(token), new Date().toISOString()]
    );
  });

  return { token, user: sanitizeUser(userRow) };
};

app.get("/api/health", asyncHandler(async (_, res) => {
  await query("SELECT 1");
  res.json({ ok: true, env: NODE_ENV });
}));

app.get("/api/articles", asyncHandler(async (_, res) => {
  const { rows } = await query(
    `SELECT * FROM articles
    WHERE published = TRUE
    ORDER BY COALESCE(published_at, created_at) DESC`
  );
  res.json(rows.map(normalizeArticle));
}));

app.get("/api/articles/:id", asyncHandler(async (req, res) => {
  const { rows } = await query(
    "SELECT * FROM articles WHERE id = $1 AND published = TRUE LIMIT 1",
    [req.params.id]
  );
  const article = rows[0];

  if (!article) {
    return res.status(404).json({ error: "Статья не найдена" });
  }

  res.json(normalizeArticle(article));
}));

app.get("/api/public/stats", asyncHandler(async (_, res) => {
  const { rows } = await query(
    "SELECT COUNT(*)::int AS users FROM users WHERE role = 'user'"
  );
  res.json({
    users: rows[0].users
  });
}));

app.post(TELEGRAM_WEBHOOK_PATH, asyncHandler(async (req, res) => {
  if (!TELEGRAM_ENABLED) {
    return res.status(503).json({ error: "Telegram bot is not configured" });
  }

  if (
    TELEGRAM_WEBHOOK_SECRET
    && req.headers["x-telegram-bot-api-secret-token"] !== TELEGRAM_WEBHOOK_SECRET
  ) {
    return res.status(403).json({ error: "Invalid Telegram webhook secret" });
  }

  res.json({ ok: true });

  try {
    await handleTelegramUpdate(req.body || {});
  } catch (error) {
    console.error("Telegram webhook handler failed", error);
  }
}));

app.get("/api/telegram/status", asyncHandler(async (_, res) => {
  res.json({
    enabled: TELEGRAM_ENABLED,
    webhookPath: TELEGRAM_WEBHOOK_PATH,
    webhookConfiguredFromSiteUrl: Boolean(TELEGRAM_WEBHOOK_URL),
    channelId: TELEGRAM_CHANNEL_ID || "",
    adminIdsCount: TELEGRAM_ADMIN_IDS.size
  });
}));

app.post("/api/register", checkAuthRateLimit, asyncHandler(async (req, res) => {
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

  let userRow;
  try {
    const { rows } = await query(
      `INSERT INTO users (
        id, username, password_hash, role, email, city, age, goal, bio, transport, diet, recycling, created_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      RETURNING *`,
      [
        makeId("user"),
        username,
        hashPassword(password),
        "user",
        String(req.body.email || "").trim(),
        String(req.body.city || "").trim(),
        String(req.body.age || "").trim(),
        String(req.body.goal || "").trim(),
        String(req.body.bio || "").trim(),
        String(req.body.transport || "").trim(),
        String(req.body.diet || "").trim(),
        String(req.body.recycling || "").trim(),
        new Date().toISOString()
      ]
    );
    userRow = rows[0];
  } catch (error) {
    if (error.code === "23505") {
      registerFailedAuthAttempt(req);
      return res.status(409).json({ error: "Пользователь уже существует" });
    }
    throw error;
  }

  const payload = await createSessionPayload(userRow);
  clearFailedAuthAttempts(req);
  res.status(201).json(payload);
}));

app.post("/api/login", checkAuthRateLimit, asyncHandler(async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "").trim();
  const { rows } = await query("SELECT * FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1", [username]);
  const user = rows[0];

  if (!user || !verifyPassword(password, user.password_hash)) {
    registerFailedAuthAttempt(req);
    return res.status(401).json({ error: "Неверный логин или пароль" });
  }

  clearFailedAuthAttempts(req);
  res.json(await createSessionPayload(user));
}));

app.post("/api/logout", requireAuth, asyncHandler(async (req, res) => {
  await query("DELETE FROM sessions WHERE id = $1", [req.auth.session.id]);
  res.json({ ok: true });
}));

app.get("/api/me", requireAuth, (req, res) => {
  res.json(req.auth.user);
});

app.get("/api/users", requireAuth, requireAdmin, asyncHandler(async (_, res) => {
  const { rows } = await query("SELECT * FROM users ORDER BY created_at DESC");
  res.json(rows.map(sanitizeUser));
}));

app.get("/api/users/:id", requireAuth, asyncHandler(async (req, res) => {
  if (req.auth.user.role !== "admin" && req.auth.user.id !== req.params.id) {
    return res.status(403).json({ error: "Недостаточно прав" });
  }

  const { rows } = await query("SELECT * FROM users WHERE id = $1 LIMIT 1", [req.params.id]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: "Пользователь не найден" });
  res.json(sanitizeUser(user));
}));

app.put("/api/users/:id", requireAuth, asyncHandler(async (req, res) => {
  if (req.auth.user.role !== "admin" && req.auth.user.id !== req.params.id) {
    return res.status(403).json({ error: "Недостаточно прав" });
  }

  const { rows } = await query("SELECT * FROM users WHERE id = $1 LIMIT 1", [req.params.id]);
  const existingUser = rows[0];
  if (!existingUser) return res.status(404).json({ error: "Пользователь не найден" });

  const nextUser = {
    ...existingUser,
    username: "username" in req.body ? String(req.body.username ?? "").trim() : existingUser.username,
    email: "email" in req.body ? String(req.body.email ?? "").trim() : existingUser.email,
    city: "city" in req.body ? String(req.body.city ?? "").trim() : existingUser.city,
    age: "age" in req.body ? String(req.body.age ?? "").trim() : existingUser.age,
    goal: "goal" in req.body ? String(req.body.goal ?? "").trim() : existingUser.goal,
    bio: "bio" in req.body ? String(req.body.bio ?? "").trim() : existingUser.bio,
    transport: "transport" in req.body ? String(req.body.transport ?? "").trim() : existingUser.transport,
    diet: "diet" in req.body ? String(req.body.diet ?? "").trim() : existingUser.diet,
    recycling: "recycling" in req.body ? String(req.body.recycling ?? "").trim() : existingUser.recycling
  };

  if (!isValidUsername(nextUser.username)) {
    return res.status(400).json({ error: "Логин должен быть длиной 3-32 символа и содержать только буквы, цифры, _, . или -" });
  }

  try {
    if ("password" in req.body && String(req.body.password || "").trim()) {
      const nextPassword = String(req.body.password).trim();
      if (nextPassword.length < 6) {
        return res.status(400).json({ error: "Пароль должен быть не короче 6 символов" });
      }

      const updatedUser = await withTransaction(async (client) => {
        const { rows: updatedRows } = await client.query(
          `UPDATE users
          SET username = $2, email = $3, city = $4, age = $5, goal = $6, bio = $7, transport = $8, diet = $9, recycling = $10, password_hash = $11
          WHERE id = $1
          RETURNING *`,
          [
            existingUser.id,
            nextUser.username,
            nextUser.email,
            nextUser.city,
            nextUser.age,
            nextUser.goal,
            nextUser.bio,
            nextUser.transport,
            nextUser.diet,
            nextUser.recycling,
            hashPassword(nextPassword)
          ]
        );

        const updated = updatedRows[0];
        const token = createSessionToken();
        await client.query("DELETE FROM sessions WHERE user_id = $1", [updated.id]);
        await client.query(
          "INSERT INTO sessions (id, user_id, token_hash, created_at) VALUES ($1, $2, $3, $4)",
          [makeId("session"), updated.id, hashToken(token), new Date().toISOString()]
        );
        return { updated, token };
      });

      return res.json({ token: updatedUser.token, user: sanitizeUser(updatedUser.updated) });
    }

    const { rows: updatedRows } = await query(
      `UPDATE users
      SET username = $2, email = $3, city = $4, age = $5, goal = $6, bio = $7, transport = $8, diet = $9, recycling = $10
      WHERE id = $1
      RETURNING *`,
      [
        existingUser.id,
        nextUser.username,
        nextUser.email,
        nextUser.city,
        nextUser.age,
        nextUser.goal,
        nextUser.bio,
        nextUser.transport,
        nextUser.diet,
        nextUser.recycling
      ]
    );

    res.json({ user: sanitizeUser(updatedRows[0]) });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Пользователь с таким логином уже существует" });
    }
    throw error;
  }
}));

app.get("/api/challenges", requireAuth, asyncHandler(async (req, res) => {
  const { rows } = await query("SELECT * FROM challenges ORDER BY created_at DESC");
  const all = rows.map(normalizeChallenge);
  if (req.auth.user.role === "admin") return res.json(all);

  const onlyActive = req.query.active === "1";
  const scoped = all.filter((challenge) => {
    const assigned = challenge.assignedUserIds || [];
    const visibleForUser = assigned.length === 0 || assigned.includes(req.auth.user.id);
    return visibleForUser && (!onlyActive || challenge.active);
  });
  res.json(scoped);
}));

app.get("/api/admin/articles", requireAuth, requireAdmin, asyncHandler(async (_, res) => {
  const { rows } = await query("SELECT * FROM articles ORDER BY created_at DESC");
  res.json(rows.map(normalizeArticle));
}));

app.post("/api/admin/articles", requireAuth, requireAdmin, runSingleUpload("cover"), asyncHandler(async (req, res) => {
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
  const { rows } = await query(
    `INSERT INTO articles (
      id, title, excerpt, content, cover_url, author_name, reading_time, published, created_at, updated_at, published_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    RETURNING *`,
    [
      makeId("article"),
      title,
      excerpt,
      content,
      req.file ? `/uploads/${req.file.filename}` : "",
      authorName || "Green Step",
      readingTime || "5 мин",
      published,
      now,
      now,
      published ? now : null
    ]
  );

  res.status(201).json(normalizeArticle(rows[0]));
}));

app.put("/api/admin/articles/:id", requireAuth, requireAdmin, runSingleUpload("cover"), asyncHandler(async (req, res) => {
  const { rows } = await query("SELECT * FROM articles WHERE id = $1 LIMIT 1", [req.params.id]);
  const existing = rows[0];
  if (!existing) return res.status(404).json({ error: "Статья не найдена" });

  const nextArticle = {
    ...existing,
    title: "title" in req.body ? String(req.body.title || "").trim() : existing.title,
    excerpt: "excerpt" in req.body ? String(req.body.excerpt || "").trim() : existing.excerpt,
    content: "content" in req.body ? String(req.body.content || "").trim() : existing.content,
    author_name: "authorName" in req.body ? String(req.body.authorName || "Green Step").trim() : existing.author_name,
    reading_time: "readingTime" in req.body ? String(req.body.readingTime || "5 мин").trim() : existing.reading_time,
    cover_url: req.file ? `/uploads/${req.file.filename}` : existing.cover_url
  };

  if (!nextArticle.title || !nextArticle.excerpt || !nextArticle.content) {
    return res.status(400).json({ error: "У статьи должны быть заголовок, описание и основной текст" });
  }

  let published = existing.published;
  if ("published" in req.body) {
    published = String(req.body.published) === "true" || req.body.published === true;
  }

  const publishedAt = published ? (existing.published_at || new Date().toISOString()) : null;
  const { rows: updatedRows } = await query(
    `UPDATE articles
    SET title = $2, excerpt = $3, content = $4, cover_url = $5, author_name = $6, reading_time = $7, published = $8, updated_at = $9, published_at = $10
    WHERE id = $1
    RETURNING *`,
    [
      existing.id,
      nextArticle.title,
      nextArticle.excerpt,
      nextArticle.content,
      nextArticle.cover_url,
      nextArticle.author_name,
      nextArticle.reading_time,
      published,
      new Date().toISOString(),
      publishedAt
    ]
  );

  res.json(normalizeArticle(updatedRows[0]));
}));

app.delete("/api/admin/articles/:id", requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const result = await query("DELETE FROM articles WHERE id = $1", [req.params.id]);
  if (result.rowCount === 0) return res.status(404).json({ error: "Статья не найдена" });
  res.json({ ok: true });
}));

app.post("/api/challenges", requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const challenge = {
    id: makeId("challenge"),
    title: String(req.body.title || "Новый челлендж").trim(),
    reward: Number(req.body.reward || 100),
    category: String(req.body.category || "Общее").trim(),
    difficulty: String(req.body.difficulty || "Средний").trim(),
    description: String(req.body.description || "").trim(),
    active: req.body.active !== false,
    assignedUserIds: Array.isArray(req.body.assignedUserIds) ? req.body.assignedUserIds.map(String) : [],
    createdAt: new Date().toISOString()
  };

  const { rows } = await query(
    `INSERT INTO challenges (
      id, title, reward, category, difficulty, description, active, assigned_user_ids, created_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    RETURNING *`,
    [
      challenge.id,
      challenge.title,
      challenge.reward,
      challenge.category,
      challenge.difficulty,
      challenge.description,
      challenge.active,
      challenge.assignedUserIds,
      challenge.createdAt
    ]
  );

  res.status(201).json(normalizeChallenge(rows[0]));
}));

app.put("/api/challenges/:id", requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const { rows } = await query("SELECT * FROM challenges WHERE id = $1 LIMIT 1", [req.params.id]);
  const existing = rows[0];
  if (!existing) return res.status(404).json({ error: "Челлендж не найден" });

  const nextChallenge = {
    ...existing,
    title: "title" in req.body ? String(req.body.title ?? "").trim() : existing.title,
    reward: "reward" in req.body ? Number(req.body.reward || 0) : Number(existing.reward || 0),
    category: "category" in req.body ? String(req.body.category ?? "").trim() : existing.category,
    difficulty: "difficulty" in req.body ? String(req.body.difficulty ?? "").trim() : existing.difficulty,
    description: "description" in req.body ? String(req.body.description ?? "").trim() : existing.description,
    active: "active" in req.body ? !!req.body.active : existing.active,
    assigned_user_ids: "assignedUserIds" in req.body
      ? (Array.isArray(req.body.assignedUserIds) ? req.body.assignedUserIds.map(String) : [])
      : (existing.assigned_user_ids || [])
  };

  const { rows: updatedRows } = await query(
    `UPDATE challenges
    SET title = $2, reward = $3, category = $4, difficulty = $5, description = $6, active = $7, assigned_user_ids = $8
    WHERE id = $1
    RETURNING *`,
    [
      existing.id,
      nextChallenge.title,
      nextChallenge.reward,
      nextChallenge.category,
      nextChallenge.difficulty,
      nextChallenge.description,
      nextChallenge.active,
      nextChallenge.assigned_user_ids
    ]
  );

  res.json(normalizeChallenge(updatedRows[0]));
}));

app.delete("/api/challenges/:id", requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const result = await query("DELETE FROM challenges WHERE id = $1", [req.params.id]);
  if (result.rowCount === 0) return res.status(404).json({ error: "Челлендж не найден" });
  res.json({ ok: true });
}));

app.get("/api/submissions", requireAuth, asyncHandler(async (req, res) => {
  let sql = "SELECT * FROM submissions";
  const params = [];

  if (req.auth.user.role !== "admin") {
    sql += " WHERE user_id = $1";
    params.push(req.auth.user.id);
  } else if (req.query.userId) {
    sql += " WHERE user_id = $1";
    params.push(String(req.query.userId));
  }

  sql += " ORDER BY created_at DESC";
  const { rows } = await query(sql, params);
  res.json(rows.map(normalizeSubmission));
}));

app.post("/api/submissions", requireAuth, (req, res, next) => {
  upload.single("photo")(req, res, (err) => {
    if (!err) return next();
    const message = err.code === "LIMIT_FILE_SIZE" ? "Файл слишком большой. Максимум 5 МБ." : err.message;
    return res.status(400).json({ error: message });
  });
}, asyncHandler(async (req, res) => {
  const user = req.auth.user;
  const { rows } = await query(
    "SELECT * FROM challenges WHERE id = $1 AND active = TRUE LIMIT 1",
    [String(req.body.challengeId || "")]
  );
  const challenge = rows[0];

  if (!challenge) {
    return res.status(400).json({ error: "Челлендж не найден или отключен" });
  }

  const assigned = Array.isArray(challenge.assigned_user_ids) ? challenge.assigned_user_ids : [];
  if (assigned.length > 0 && !assigned.includes(user.id)) {
    return res.status(403).json({ error: "Этот челлендж не назначен данному пользователю" });
  }

  if (!req.file) {
    return res.status(400).json({ error: "Прикрепи фото" });
  }

  const { rows: submissionRows } = await query(
    `INSERT INTO submissions (
      id, user_id, username, challenge_id, challenge_title, reward, comment, photo_url, status, admin_comment, created_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    RETURNING *`,
    [
      makeId("submission"),
      user.id,
      user.username,
      challenge.id,
      challenge.title,
      Number(challenge.reward || 0),
      String(req.body.comment || "").trim(),
      `/uploads/${req.file.filename}`,
      "pending",
      "",
      new Date().toISOString()
    ]
  );

  res.status(201).json(normalizeSubmission(submissionRows[0]));
}));

app.patch("/api/submissions/:id", requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const { rows } = await query("SELECT * FROM submissions WHERE id = $1 LIMIT 1", [req.params.id]);
  const existing = rows[0];
  if (!existing) return res.status(404).json({ error: "Заявка не найдена" });

  const nextStatus = ["pending", "approved", "rejected", "paid"].includes(req.body.status)
    ? req.body.status
    : existing.status;
  const nextAdminComment = "adminComment" in req.body
    ? String(req.body.adminComment || "").trim()
    : existing.admin_comment;

  const updatedSubmission = await withTransaction(async (client) => {
    const { rows: updatedRows } = await client.query(
      `UPDATE submissions
      SET status = $2, admin_comment = $3
      WHERE id = $1
      RETURNING *`,
      [existing.id, nextStatus, nextAdminComment]
    );
    const updated = updatedRows[0];

    if (updated.status === "paid") {
      await client.query(
        `INSERT INTO payouts (id, submission_id, user_id, username, amount, created_at)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (submission_id) DO NOTHING`,
        [
          makeId("payout"),
          updated.id,
          updated.user_id,
          updated.username,
          Number(updated.reward || 0),
          new Date().toISOString()
        ]
      );
    }

    return updated;
  });

  res.json(normalizeSubmission(updatedSubmission));
}));

app.get("/api/payouts", requireAuth, requireAdmin, asyncHandler(async (_, res) => {
  const { rows } = await query("SELECT * FROM payouts ORDER BY created_at DESC");
  res.json(rows.map(normalizePayout));
}));

app.get("/api/admin/stats", requireAuth, requireAdmin, asyncHandler(async (_, res) => {
  const [users, challenges, activeChallenges, submissions, pending, approved, rejected, payouts, totalPaid] = await Promise.all([
    query("SELECT COUNT(*)::int AS count FROM users"),
    query("SELECT COUNT(*)::int AS count FROM challenges"),
    query("SELECT COUNT(*)::int AS count FROM challenges WHERE active = TRUE"),
    query("SELECT COUNT(*)::int AS count FROM submissions"),
    query("SELECT COUNT(*)::int AS count FROM submissions WHERE status = 'pending'"),
    query("SELECT COUNT(*)::int AS count FROM submissions WHERE status IN ('approved', 'paid')"),
    query("SELECT COUNT(*)::int AS count FROM submissions WHERE status = 'rejected'"),
    query("SELECT COUNT(*)::int AS count FROM payouts"),
    query("SELECT COALESCE(SUM(amount), 0)::int AS total FROM payouts")
  ]);

  res.json({
    users: users.rows[0].count,
    challenges: challenges.rows[0].count,
    activeChallenges: activeChallenges.rows[0].count,
    submissions: submissions.rows[0].count,
    pending: pending.rows[0].count,
    approved: approved.rows[0].count,
    rejected: rejected.rows[0].count,
    payouts: payouts.rows[0].count,
    totalPaid: totalPaid.rows[0].total
  });
}));

app.get("/", (_, res) => {
  res.sendFile(path.join(FRONTEND_DIR, "index.html"));
});

app.get("/admin", (_, res) => {
  res.sendFile(path.join(FRONTEND_DIR, "admin.html"));
});

app.get("/user", (_, res) => {
  res.sendFile(path.join(FRONTEND_DIR, "user.html"));
});

app.get("/auth", (_, res) => {
  res.sendFile(path.join(FRONTEND_DIR, "auth.html"));
});

app.get("/article", (_, res) => {
  res.sendFile(path.join(FRONTEND_DIR, "article.html"));
});

app.use((err, _, res, __) => {
  console.error(err);
  res.status(500).json({ error: "Внутренняя ошибка сервера" });
});

const startServer = async () => {
  await initDatabase({
    hashPassword,
    defaultAdminPassword: DEFAULT_ADMIN_PASSWORD,
    legacyPaths: [legacyStorageDbPath, legacyDataPath]
  });

  app.listen(PORT, () => {
    console.log(`Green Step backend running on http://localhost:${PORT} (${NODE_ENV})`);
  });

  try {
    await setupTelegramWebhook();
  } catch (error) {
    console.error("Failed to configure Telegram webhook", error);
  }
};

startServer().catch((error) => {
  console.error("Failed to start server", error);
  process.exit(1);
});
