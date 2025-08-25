const crypto = require("crypto");
const bcrypt = require("bcrypt");

const ENC_KEY = (
  process.env.TOTP_ENC_KEY || "CHANGE_ME_TO_32_CHARS_MINIMUM_1234567890!"
).slice(0, 32);
const IV_LEN = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(ENC_KEY), iv);
  let enc = cipher.update(text, "utf8", "base64");
  enc += cipher.final("base64");
  return iv.toString("base64") + ":" + enc;
}

function decrypt(payload) {
  if (!payload) return null;
  const [ivB64, dataB64] = payload.split(":");
  const iv = Buffer.from(ivB64, "base64");
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(ENC_KEY),
    iv
  );
  let dec = decipher.update(dataB64, "base64", "utf8");
  dec += decipher.final("utf8");
  return dec;
}

async function hashString(str) {
  return bcrypt.hash(str, 10);
}
async function compareHash(str, hash) {
  return bcrypt.compare(str, hash);
}

module.exports = { encrypt, decrypt, hashString, compareHash };
