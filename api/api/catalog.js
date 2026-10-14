
const crypto = require("crypto");

const ADMIN_IDS = new Set(["7535464331", "8404412552"]);
const FILE_PATH = "data/catalog.json";

function verifyInitData(initData) {
  if (!initData || !process.env.BOT_TOKEN) return null;

  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) return null;

  const authDate = Number(params.get("auth_date"));
  const now = Math.floor(Date.now() / 1000);

  if (
    !Number.isFinite(authDate) ||
    authDate > now + 60 ||
    now - authDate > 86400
  ) return null;

  const checkString = [...params.entries()]
    .filter(([key]) => key !== "hash")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secret = crypto
    .createHmac("sha256", "WebAppData")
    .update(process.env.BOT_TOKEN)
    .digest();

  const calculated = crypto
    .createHmac("sha256", secret)
    .update(checkString)
    .digest();

  const received = Buffer.from(hash, "hex");

  if (
    calculated.length !== received.length ||
    !crypto.timingSafeEqual(calculated, received)
  ) return null;

  try {
    return JSON.parse(params.get("user") || "null");
  } catch {
    return null;
  }
}

function githubConfig() {
  const { GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO } = process.env;

  if (!GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO) {
    throw new Error("Не настроены переменные GitHub в Vercel");
  }

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

  try {
    result = text ? JSON.parse(text) : {};
  } catch {}

  if (!response.ok && response.status !== 404) {
    console.error("GitHub API error:", response.status, result.message);
    const error = new Error(result.message || "GitHub API error");
    error.status = response.status;
    throw error;
  }

  return {
    status: response.status,
    data: result
  };
}

async function readCatalog() {
  const config = githubConfig();

  const query = new URLSearchParams({ ref: config.branch });

  const result = await githubRequest(
    `${FILE_PATH}?${query.toString()}`
  );

  if (result.status === 404) {
    return {
      categories: [],
      products: [],
      sha: null
    };
  }

  const content = Buffer.from(
    result.data.content.replace(/\s/g, ""),
    "base64"
  ).toString("utf8");

  const catalog = JSON.parse(content);

  if (
    !catalog ||
    !Array.isArray(catalog.categories) ||
    !Array.isArray(catalog.products)
  ) {
    throw new Error("Некорректный JSON каталога");
  }

  return {
    ...catalog,
    sha: result.data.sha
  };
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "GET") {
    try {
      const catalog = await readCatalog();
      delete catalog.sha;

      return res.status(200).json(catalog);
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        error: "Не удалось загрузить каталог"
      });
    }
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({
      error: "Метод не поддерживается"
    });
  }

  try {
    const body = req.body || {};
    const user = verifyInitData(body.initData);

    if (!user || !ADMIN_IDS.has(String(user.id))) {
      return res.status(403).json({
        error: "Нет доступа к сохранению каталога"
      });
    }

    const catalog = body.catalog;

    if (
      !catalog ||
      !Array.isArray(catalog.categories) ||
      !Array.isArray(catalog.products)
    ) {
      return res.status(400).json({
        error: "Некорректный формат каталога"
      });
    }

    const json = JSON.stringify({
      categories: catalog.categories,
      products: catalog.products
    }, null, 2);

    if (Buffer.byteLength(json, "utf8") > 2_500_000) {
      return res.status(413).json({
        error: "Каталог слишком большой. Используй ссылки на изображения."
      });
    }

    const current = await readCatalog();
    const config = githubConfig();

    const payload = {
      message: "Update Destore catalog",
      content: Buffer.from(json, "utf8").toString("base64"),
      branch: config.branch
    };

    if (current.sha) payload.sha = current.sha;

    const result = await githubRequest(FILE_PATH, {
      method: "PUT",
      body: JSON.stringify(payload)
    });

    if (result.status !== 200 && result.status !== 201) {
      return res.status(502).json({
        error: "GitHub не подтвердил сохранение"
      });
    }

    return res.status(200).json({
      ok: true,
      message: "Каталог сохранён"
    });
  } catch (error) {
    console.error(error);

    if (error.status === 409 || error.status === 422) {
      return res.status(409).json({
        error: "Каталог изменился одновременно. Обнови его и попробуй снова."
      });
    }

    return res.status(500).json({
      error: "Ошибка сохранения каталога"
    });
  }
};
