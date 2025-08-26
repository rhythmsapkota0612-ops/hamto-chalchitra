const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Session = require("../models/session");

const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";

function getClientMeta(req) {
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket.remoteAddress ||
    "";
  const userAgent = req.headers["user-agent"] || "unknown";
  // Prefer explicit device id from client; else a stable-ish fingerprint:
  const provided =
    req.headers["x-device-id"] || req.body?.deviceId || req.query?.deviceId;
  const fallback = crypto
    .createHash("sha256")
    .update(userAgent + "|" + ip)
    .digest("hex")
    .slice(0, 32);
  return { ip, userAgent, deviceId: provided || fallback };
}

async function createSession(userId, req) {
  const meta = getClientMeta(req);
  const session = await Session.create({
    userId,
    deviceId: meta.deviceId,
    userAgent: meta.userAgent,
    ip: meta.ip,
  });
  return session;
}

async function revokeOldestSessionsIfNeeded(user, keepSessionId) {
  const max = Math.max(1, user.maxDevices || 1);
  // active = not revoked
  const active = await Session.find({ userId: user._id, revokedAt: null }).sort(
    { createdAt: 1 }
  );
  if (active.length <= max) return;

  const toRevoke = active
    .filter((s) => s.id !== keepSessionId)
    .slice(0, active.length - max);
  if (toRevoke.length) {
    await Session.updateMany(
      { _id: { $in: toRevoke.map((s) => s._id) } },
      { $set: { revokedAt: new Date() } }
    );
  }
}

function signFinalToken(user, session) {
  return jwt.sign(
    {
      id: user._id,
      username: user.username,
      role: user.role,
      mfa: true,
      sid: session._id.toString(),
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

async function validateFinalTokenAndSession(token) {
  const payload = jwt.verify(token, JWT_SECRET);
  if (!payload?.mfa || !payload?.sid) throw new Error("MFA or session missing");
  const session = await Session.findById(payload.sid);
  if (!session || session.revokedAt) throw new Error("Session revoked");
  return { payload, session };
}

module.exports = {
  getClientMeta,
  createSession,
  revokeOldestSessionsIfNeeded,
  signFinalToken,
  validateFinalTokenAndSession,
};
