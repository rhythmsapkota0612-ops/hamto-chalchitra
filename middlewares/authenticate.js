const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const Session = require("../models/session");
const { validateFinalTokenAndSession } = require("../utils/auth");

const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";

const MFA_EXEMPT = new Set([
  "/auth/register",
  "/auth/login",
  "/auth/2fa/setup",
  "/auth/2fa/verify-setup",
  "/auth/2fa/login",
  "/auth/forgot-password",
  "/auth/reset-password",
]);

module.exports = async function authenticateToken(req, res, next) {
  try {
    // Allow public endpoints to pass through
    if (MFA_EXEMPT.has(req.path)) return next();

    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) {
      return res.status(401).json({
        success: false,
        error: "Missing token",
        code: "MISSING_TOKEN",
      });
    }

    // Preferred: helper validates final token + live session
    const { payload, session } = await validateFinalTokenAndSession(token);

    req.user = {
      id: payload.id,
      username: payload.username,
      role: payload.role,
    };
    req.session = { id: session._id.toString(), deviceId: session.deviceId };
    return next();
  } catch (e) {
    // Fallback: try to decode to detect *why* it failed and return specific codes
    try {
      const auth = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      if (!token) {
        return res.status(401).json({
          success: false,
          error: "Missing token",
          code: "MISSING_TOKEN",
        });
      }

      let payload;
      try {
        payload = jwt.verify(token, JWT_SECRET);
      } catch {
        return res.status(401).json({
          success: false,
          error: "Invalid or expired token",
          code: "INVALID_TOKEN",
        });
      }

      // Must be a final, MFA-verified token
      if (payload.stage || !payload.mfa) {
        return res.status(401).json({
          success: false,
          error: "MFA required",
          code: "MFA_REQUIRED",
        });
      }

      if (!payload.sid || !mongoose.Types.ObjectId.isValid(payload.sid)) {
        return res.status(401).json({
          success: false,
          error: "Invalid session",
          code: "INVALID_SESSION",
        });
      }

      const sess = await Session.findById(payload.sid);
      if (!sess) {
        return res.status(401).json({
          success: false,
          error: "Session not found",
          code: "INVALID_SESSION",
        });
      }

      if (sess.revokedAt) {
        // This is the case you asked for: when device limit kicked the user out
        return res.status(409).json({
          success: false,
          error:
            "Your session was revoked (likely due to device limit or admin action). Please log in again.",
          code: "SESSION_REVOKED_DEVICE_LIMIT",
          meta: {
            sessionId: sess._id.toString(),
            revokedAt: sess.revokedAt,
          },
        });
      }

      // If we got here, something else went wrong—treat as unauthorized
      return res.status(401).json({
        success: false,
        error: "Unauthorized",
        code: "UNAUTHORIZED",
      });
    } catch {
      return res.status(401).json({
        success: false,
        error: "Unauthorized",
        code: "UNAUTHORIZED",
      });
    }
  }
};
