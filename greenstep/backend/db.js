import fs from "fs";
import pg from "pg";

const { Pool } = pg;

const connectionString = process.env.DATABASE_URL || "";

if (!connectionString) {
  throw new Error("DATABASE_URL is required to start the backend");
}

const pool = new Pool({
  connectionString,
  ssl: process.env.PGSSLMODE === "require" || process.env.DATABASE_SSL === "true"
    ? { rejectUnauthorized: false }
    : undefined
});

const readLegacyJson = (filePath) => {
  if (!filePath || !fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch {
    return null;
  }
};

const normalizeLegacyData = (legacyData, { hashPassword, defaultAdminPassword }) => {
  const now = new Date().toISOString();
  const data = legacyData || {};

  const users = Array.isArray(data.users) ? data.users.map((user, index) => {
    const plainPassword = String(user.password || "");
    const passwordHash = user.passwordHash
      || (user.id === "admin_1" || user.username === "admin"
        ? hashPassword(defaultAdminPassword)
        : hashPassword(plainPassword || "123456"));

    return {
      id: String(user.id || `user_seed_${index + 1}`),
      username: String(user.username || `user${index + 1}`),
      passwordHash,
      role: String(user.role || "user"),
      email: String(user.email || ""),
      city: String(user.city || ""),
      age: String(user.age || ""),
      goal: String(user.goal || ""),
      bio: String(user.bio || ""),
      transport: String(user.transport || ""),
      diet: String(user.diet || ""),
      recycling: String(user.recycling || ""),
      createdAt: user.createdAt || now
    };
  }) : [];

  const challenges = Array.isArray(data.challenges) ? data.challenges.map((challenge, index) => ({
    id: String(challenge.id || `challenge_seed_${index + 1}`),
    title: String(challenge.title || "Новый челлендж"),
    reward: Number(challenge.reward || 0),
    category: String(challenge.category || "Общее"),
    difficulty: String(challenge.difficulty || "Средний"),
    description: String(challenge.description || ""),
    active: challenge.active !== false,
    assignedUserIds: Array.isArray(challenge.assignedUserIds) ? challenge.assignedUserIds.map(String) : [],
    createdAt: challenge.createdAt || now
  })) : [];

  const articles = Array.isArray(data.articles) ? data.articles.map((article, index) => ({
    id: String(article.id || `article_seed_${index + 1}`),
    title: String(article.title || ""),
    excerpt: String(article.excerpt || ""),
    content: String(article.content || ""),
    coverUrl: String(article.coverUrl || ""),
    videoUrl: String(article.videoUrl || ""),
    authorName: String(article.authorName || "Green Step"),
    readingTime: String(article.readingTime || "5 мин"),
    published: !!article.published,
    createdAt: article.createdAt || now,
    updatedAt: article.updatedAt || article.createdAt || now,
    publishedAt: article.published ? (article.publishedAt || article.createdAt || now) : null
  })) : [];

  const submissions = Array.isArray(data.submissions) ? data.submissions.map((submission, index) => ({
    id: String(submission.id || `submission_seed_${index + 1}`),
    userId: String(submission.userId || ""),
    username: String(submission.username || ""),
    challengeId: String(submission.challengeId || ""),
    challengeTitle: String(submission.challengeTitle || ""),
    reward: Number(submission.reward || 0),
    comment: String(submission.comment || ""),
    photoUrl: String(submission.photoUrl || ""),
    status: String(submission.status || "pending"),
    adminComment: String(submission.adminComment || ""),
    createdAt: submission.createdAt || now
  })) : [];

  const payouts = Array.isArray(data.payouts) ? data.payouts.map((payout, index) => ({
    id: String(payout.id || `payout_seed_${index + 1}`),
    submissionId: String(payout.submissionId || ""),
    userId: String(payout.userId || ""),
    username: String(payout.username || ""),
    amount: Number(payout.amount || 0),
    createdAt: payout.createdAt || now
  })) : [];

  const sessions = Array.isArray(data.sessions) ? data.sessions
    .filter((session) => session?.tokenHash && session?.userId)
    .map((session, index) => ({
      id: String(session.id || `session_seed_${index + 1}`),
      userId: String(session.userId),
      tokenHash: String(session.tokenHash),
      createdAt: session.createdAt || now
    })) : [];

  return { users, challenges, articles, submissions, payouts, sessions };
};

const builtInSeed = ({ hashPassword, defaultAdminPassword }) => normalizeLegacyData(
  {
    users: [
      {
        id: "admin_1",
        username: "admin",
        role: "admin",
        email: "admin@greenstep.local",
        city: "Москва",
        goal: "Управлять платформой",
        bio: "Системный администратор"
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
        recycling: "Сортирую пластик и бумагу"
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
        active: true
      },
      {
        id: "challenge_demo_2",
        title: "3 поездки без автомобиля",
        reward: 200,
        category: "Транспорт",
        difficulty: "Средний",
        description: "Выбирай пешие маршруты, велосипед или общественный транспорт.",
        active: true
      }
    ],
    articles: [
      {
        id: "article_demo_1",
        title: "Как начать экологичные привычки без перегруза",
        excerpt: "Небольшие шаги, которые проще внедрить в повседневную жизнь и не бросить через неделю.",
        content: "Начни с одной привычки: многоразовая бутылка, отказ от лишних пакетов или короткие пешие маршруты. Когда действие становится частью рутины, добавляй следующее.",
        authorName: "Команда Green Step",
        readingTime: "4 мин",
        published: true
      },
      {
        id: "article_demo_2",
        title: "Почему маленькие челленджи работают лучше больших обещаний",
        excerpt: "Экологичный прогресс устойчивее, когда он измерим и привязан к понятному действию.",
        content: "Большие цели демотивируют, если они слишком размыты. Челлендж помогает превратить намерение в конкретное действие, которое можно проверить и повторить.",
        authorName: "Команда Green Step",
        readingTime: "3 мин",
        published: true
      }
    ]
  },
  { hashPassword, defaultAdminPassword }
);

const seedFromLegacySources = ({ legacyPaths, hashPassword, defaultAdminPassword }) => {
  for (const legacyPath of legacyPaths) {
    const legacyData = readLegacyJson(legacyPath);
    if (legacyData?.users?.length) {
      return normalizeLegacyData(legacyData, { hashPassword, defaultAdminPassword });
    }
  }

  return builtInSeed({ hashPassword, defaultAdminPassword });
};

const createSchema = async (client) => {
  await client.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      email TEXT NOT NULL DEFAULT '',
      city TEXT NOT NULL DEFAULT '',
      age TEXT NOT NULL DEFAULT '',
      goal TEXT NOT NULL DEFAULT '',
      bio TEXT NOT NULL DEFAULT '',
      transport TEXT NOT NULL DEFAULT '',
      diet TEXT NOT NULL DEFAULT '',
      recycling TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await client.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx
    ON users (LOWER(username));
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS challenges (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      reward INTEGER NOT NULL DEFAULT 0,
      category TEXT NOT NULL DEFAULT '',
      difficulty TEXT NOT NULL DEFAULT '',
      description TEXT NOT NULL DEFAULT '',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      assigned_user_ids TEXT[] NOT NULL DEFAULT '{}',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS articles (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      excerpt TEXT NOT NULL DEFAULT '',
      content TEXT NOT NULL DEFAULT '',
      cover_url TEXT NOT NULL DEFAULT '',
      video_url TEXT NOT NULL DEFAULT '',
      author_name TEXT NOT NULL DEFAULT 'Green Step',
      reading_time TEXT NOT NULL DEFAULT '5 мин',
      published BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      published_at TIMESTAMPTZ
    );
  `);

  await client.query(`
    ALTER TABLE articles
    ADD COLUMN IF NOT EXISTS video_url TEXT NOT NULL DEFAULT '';
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS submissions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      username TEXT NOT NULL,
      challenge_id TEXT NOT NULL,
      challenge_title TEXT NOT NULL,
      reward INTEGER NOT NULL DEFAULT 0,
      comment TEXT NOT NULL DEFAULT '',
      photo_url TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      admin_comment TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS payouts (
      id TEXT PRIMARY KEY,
      submission_id TEXT NOT NULL UNIQUE REFERENCES submissions(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      username TEXT NOT NULL,
      amount INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS bot_sessions (
      id TEXT PRIMARY KEY,
      telegram_user_id TEXT NOT NULL UNIQUE,
      state TEXT NOT NULL,
      payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
};

const insertSeedData = async (client, seed) => {
  for (const user of seed.users) {
    await client.query(
      `INSERT INTO users (
        id, username, password_hash, role, email, city, age, goal, bio, transport, diet, recycling, created_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        user.id,
        user.username,
        user.passwordHash,
        user.role,
        user.email,
        user.city,
        user.age,
        user.goal,
        user.bio,
        user.transport,
        user.diet,
        user.recycling,
        user.createdAt
      ]
    );
  }

  for (const challenge of seed.challenges) {
    await client.query(
      `INSERT INTO challenges (
        id, title, reward, category, difficulty, description, active, assigned_user_ids, created_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
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
  }

  for (const article of seed.articles) {
    await client.query(
      `INSERT INTO articles (
        id, title, excerpt, content, cover_url, video_url, author_name, reading_time, published, created_at, updated_at, published_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        article.id,
        article.title,
        article.excerpt,
        article.content,
        article.coverUrl,
        article.videoUrl,
        article.authorName,
        article.readingTime,
        article.published,
        article.createdAt,
        article.updatedAt,
        article.publishedAt
      ]
    );
  }

  for (const submission of seed.submissions) {
    await client.query(
      `INSERT INTO submissions (
        id, user_id, username, challenge_id, challenge_title, reward, comment, photo_url, status, admin_comment, created_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        submission.id,
        submission.userId,
        submission.username,
        submission.challengeId,
        submission.challengeTitle,
        submission.reward,
        submission.comment,
        submission.photoUrl,
        submission.status,
        submission.adminComment,
        submission.createdAt
      ]
    );
  }

  for (const payout of seed.payouts) {
    if (!payout.submissionId) continue;
    await client.query(
      `INSERT INTO payouts (
        id, submission_id, user_id, username, amount, created_at
      ) VALUES ($1,$2,$3,$4,$5,$6)
      ON CONFLICT (submission_id) DO NOTHING`,
      [
        payout.id,
        payout.submissionId,
        payout.userId,
        payout.username,
        payout.amount,
        payout.createdAt
      ]
    );
  }

  for (const session of seed.sessions) {
    await client.query(
      `INSERT INTO sessions (
        id, user_id, token_hash, created_at
      ) VALUES ($1,$2,$3,$4)
      ON CONFLICT (token_hash) DO NOTHING`,
      [
        session.id,
        session.userId,
        session.tokenHash,
        session.createdAt
      ]
    );
  }
};

export const query = (text, params = []) => pool.query(text, params);

export const withTransaction = async (handler) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await handler(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
};

export const initDatabase = async ({ hashPassword, defaultAdminPassword, legacyPaths = [] }) => {
  await withTransaction(async (client) => {
    await createSchema(client);

    const { rows } = await client.query("SELECT COUNT(*)::int AS count FROM users");
    if (rows[0].count > 0) return;

    const seed = seedFromLegacySources({ legacyPaths, hashPassword, defaultAdminPassword });
    await insertSeedData(client, seed);
  });
};

export const closeDatabase = async () => {
  await pool.end();
};
