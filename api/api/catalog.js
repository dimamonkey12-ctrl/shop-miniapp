const crypto = require("crypto");

const FILE_PATH = process.env.CATALOG_FILE_PATH || "data/catalog.json";

function getAdminIds() {
  const raw = process.env.ADMIN_IDS || "7535464331,8404412552";
  return new Set(raw.split(",").map(s => s.trim()).filter(Boolean));
}

function verifyInitData(initData) {
  if (!initData || !process.env.BOT_TOKEN) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) return null;
  const authDate = Number(params.get("auth_date"));
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(authDate) || authDate > now + 60 || now - authDate > 86400) return null;
  const checkString = [...params.entries()]
    .filter(([k]) => k !== "hash")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`).join("\n");
  const secret = crypto.createHmac("sha256", "WebAppData").update(process.env.BOT_TOKEN).digest();
  const calculated = crypto.createHmac("sha256", secret).update(checkString).digest();
  const received = Buffer.from(hash, "hex");
  if (calculated.length !== received.length || !crypto.timingSafeEqual(calculated, received)) return null;
  try { return JSON.parse(params.get("user") || "null"); } catch { return null; }
}

function githubConfig() {
  const { GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO } = process.env;
  if (!GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO) throw new Error("Не настроены переменные GitHub в Vercel");
  return {
    token: GITHUB_TOKEN,
    owner: GITHUB_OWNER,
    repo: GITHUB_REPO,
    branch: process.env.GITHUB_BRANCH || "main"
  };
}

async function githubRequest(path, options = {}) {
  const config = githubConfig();
  const response = await fetch(
    `https://api.github.com/repos/${config.owner}/${config.repo}/contents/${path}`,
    {
      ...options,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${config.token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        ...options.headers
      }
    }
  );
  const text = await response.text();
  let result = {};
  try { result = text ? JSON.parse(text) : {}; } catch {}
  if (!response.ok && response.status !== 404) {
    const error = new Error(result.message || "GitHub API error");
    error.status = response.status;
    throw error;
  }
  return { status: response.status, data: result };
}

async function readCatalog() {
  const config = githubConfig();
  const query = new URLSearchParams({ ref: config.branch });
  const result = await githubRequest(`${FILE_PATH}?${query.toString()}`);
  if (result.status === 404) return { categories: [], products: [], sha: null };
  const content = Buffer.from(result.data.content.replace(/\s/g, ""), "base64").toString("utf8");
  let catalog;
  try { catalog = JSON.parse(content); } catch { throw new Error("Некорректный JSON каталога"); }
  if (!catalog || !Array.isArray(catalog.categories) || !Array.isArray(catalog.products)) {
    throw new Error("Некорректная структура каталога");
  }
  return { ...catalog, sha: result.data.sha };
}

// Пытаемся сохранить. При 409 (SHA устарел) — перечитываем и пробуем ещё раз.
async function writeCatalogWithRetry(json, user) {
  const config = githubConfig();
  const maxAttempts = 3;
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const current = await readCatalog();
    const payload = {
      message: `Update catalog (${user.id})`,
      content: Buffer.from(json, "utf8").toString("base64"),
      branch: config.branch
    };
    if (current.sha) payload.sha = current.sha;

    try {
      const result = await githubRequest(FILE_PATH, {
        method: "PUT",
        body: JSON.stringify(payload)
      });
      if (result.status === 200 || result.status === 201) return { ok: true };
      lastError = new Error("GitHub не подтвердил сохранение");
      lastError.status = result.status;
    } catch (err) {
      lastError = err;
    }

    // 409 или 422 → повторить с новым sha
    if (lastError && (lastError.status === 409 || lastError.status === 422)) {
      console.warn(`Catalog save conflict, retry ${attempt}/${maxAttempts}`);
      await new Promise(r => setTimeout(r, 300 * attempt));
      continue;
    }
    // другая ошибка — выбрасываем
    throw lastError;
  }
  throw lastError || new Error("Не удалось сохранить");
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  if (req.method === "OPTIONS") {
    res.setHeader("Allow", "GET, POST, OPTIONS");
    return res.status(204).end();
  }

  if (req.method === "GET") {
    try {
      const catalog = await readCatalog();
      delete catalog.sha;
      return res.status(200).json(catalog);
    } catch (error) {
      console.error("GET /catalog error:", error);
      return res.status(500).json({ error: "Не удалось загрузить каталог" });
    }
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST, OPTIONS");
    return res.status(405).json({ error: "Метод не поддерживается" });
  }

  try {
    const body = req.body || {};
    const user = verifyInitData(body.initData);
    if (!user || !getAdminIds().has(String(user.id))) {
      return res.status(403).json({ error: "Нет доступа к сохранению каталога" });
    }

    const catalog = body.catalog;
    if (!catalog || !Array.isArray(catalog.categories) || !Array.isArray(catalog.products)) {
      return res.status(400).json({ error: "Некорректный формат каталога" });
    }

    const json = JSON.stringify({ categories: catalog.categories, products: catalog.products }, null, 2);
    if (Buffer.byteLength(json, "utf8") > 2_500_000) {
      return res.status(413).json({ error: "Каталог слишком большой. Используй ссылки на изображения." });
    }

    const result = await writeCatalogWithRetry(json, user);
    if (!result.ok) return res.status(502).json({ error: "GitHub не подтвердил сохранение" });

    return res.status(200).json({ ok: true, message: "Каталог сохранён" });
  } catch (error) {
    console.error("POST /catalog error:", error);
    if (error.status === 409 || error.status === 422) {
      return res.status(409).json({ error: "Каталог изменился. Обнови страницу и повтори." });
    }
    return res.status(500).json({ error: error.message || "Ошибка сохранения каталога" });
  }
};
