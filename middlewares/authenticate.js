const jwt = require("jsonwebtoken");
const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";

// Exempt these paths from needing a final MFA token
const MFA_EXEMPT = new Set([
  "/auth/register",
  "/auth/login",
  "/auth/2fa/setup",
  "/auth/2fa/verify-setup",
  "/auth/2fa/login",
]);

module.exports = function authenticateToken(req, res, next) {
  try {
    // Allow MFA-exempt endpoints to pass without final token
    const path = req.path;
    if (MFA_EXEMPT.has(path)) return next();

    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token)
      return res.status(401).json({ success: false, error: "Missing token" });

    const payload = jwt.verify(token, JWT_SECRET);

    // Reject short-lived setup or mfa tokens (those have 'stage'), and enforce mfa:true
    if (payload.stage || !payload.mfa) {
      return res.status(401).json({ success: false, error: "MFA required" });
    }

    // Attach to req.user for your routes
    req.user = {
      id: payload.id,
      username: payload.username,
      role: payload.role || undefined,
    };
    next();
  } catch (e) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
};
