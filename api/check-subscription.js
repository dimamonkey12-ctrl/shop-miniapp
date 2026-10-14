
const crypto = require("crypto");

const BOT_TOKEN = process.env.BOT_TOKEN;
const CHANNEL = "@desiresale";
const MAX_AGE_SECONDS = 60 * 60 * 24;

function verifyTelegramInitData(initData) {
  if (typeof initData !== "string" || !initData || !BOT_TOKEN) {
    return null;
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");
  const authDate = Number(params.get("auth_date"));

  if (!receivedHash || !Number.isFinite(authDate)) return null;

  const now = Math.floor(Date.now() / 1000);
  if (authDate > now + 60 || now - authDate > MAX_AGE_SECONDS) {
    return null;
  }

  const dataCheckString = [...params.entries()]
    .filter(([key]) => key !== "hash")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(BOT_TOKEN)
    .digest();

  const expectedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  const actual = Buffer.from(receivedHash, "hex");
  const expected = Buffer.from(expectedHash, "hex");

  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) {
    return null;
  }

  try {
    const user = JSON.parse(params.get("user") || "null");
    return user && Number.isSafeInteger(user.id) ? user : null;
  } catch {
    return null;
  }
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  if (!BOT_TOKEN) {
    return res.status(500).json({
      error: "BOT_TOKEN не настроен в Vercel"
    });
  }

  const user = verifyTelegramInitData(req.body?.initData);

  if (!user) {
    return res.status(401).json({
      error: "Не удалось проверить Telegram. Открой приложение заново."
    });
  }

  try {
    const url = new URL(
      `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember`
    );
    url.searchParams.set("chat_id", CHANNEL);
    url.searchParams.set("user_id", String(user.id));

    const response = await fetch(url);
    const result = await response.json();

    if (!response.ok || !result.ok) {
      console.error("Telegram API error:", result.description);

      return res.status(502).json({
        error: "Не удалось проверить подписку. Проверь права бота в канале."
      });
    }

    const member = result.result;

    const subscribed =
      member.status === "creator" ||
      member.status === "administrator" ||
      member.status === "member" ||
      (member.status === "restricted" && member.is_member === true);

    return res.status(200).json({ subscribed });
  } catch (error) {
    console.error("Subscription check error:", error);

    return res.status(502).json({
      error: "Ошибка связи с Telegram. Попробуй ещё раз."
    });
  }
};

