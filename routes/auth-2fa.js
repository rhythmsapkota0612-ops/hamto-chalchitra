const express = require("express");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const rateLimit = require("express-rate-limit");

const User = require("../models/user");
const {
  encrypt,
  decrypt,
  hashString,
  compareHash,
} = require("../utils/crypto");

// Config comes from your main file via process.env or defaults
const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";
const MFA_TOKEN_TTL = process.env.MFA_TOKEN_TTL || "5m";

const router = express.Router();

// --- lightweight token validators for setup/mfa steps ---
function useBearerOrBodyToken(req) {
  const auth = req.headers.authorization || "";
  return auth.startsWith("Bearer ")
    ? auth.slice(7)
    : req.body?.mfa_token || null;
}

function requireSetupToken(req, res, next) {
  try {
    const token = useBearerOrBodyToken(req);
    if (!token)
      return res
        .status(401)
        .json({ success: false, error: "Missing mfa_token" });
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.stage !== "setup")
      return res
        .status(401)
        .json({ success: false, error: "Invalid setup token" });
    req.userId = payload.sub;
    next();
  } catch {
    return res
      .status(401)
      .json({ success: false, error: "Invalid or expired mfa_token" });
  }
}

function requireMfaStageToken(req, res, next) {
  try {
    const token = useBearerOrBodyToken(req);
    if (!token)
      return res
        .status(401)
        .json({ success: false, error: "Missing mfa_token" });
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.stage !== "mfa")
      return res
        .status(401)
        .json({ success: false, error: "Invalid MFA token" });
    req.userId = payload.sub;
    next();
  } catch {
    return res
      .status(401)
      .json({ success: false, error: "Invalid or expired mfa_token" });
  }
}

// Optional brute-force limiter on /login step
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

// --- 1) Begin setup: issue temp secret + QR (uses setup token) ---
router.post("/setup", requireSetupToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user)
      return res.status(404).json({ success: false, error: "User not found" });

    const secret = speakeasy.generateSecret({
      name: `Hamro App (${user.username})`,
      length: 20,
    });

    user.twoFA.tempSecretEnc = encrypt(secret.base32);
    await user.save();

    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.json({
      success: true,
      qrDataUrl,
      secretBase32: secret.base32, // show as fallback on UI
    });
  } catch (e) {
    console.error("2FA setup error:", e);
    res.status(500).json({ success: false, error: "2FA setup failed" });
  }
});

// --- 2) Verify setup: confirm OTP, enable 2FA, issue backup codes ---
router.post("/verify-setup", requireSetupToken, async (req, res) => {
  try {
    const { token } = req.body; // 6-digit OTP
    if (!token)
      return res.status(400).json({ success: false, error: "OTP required" });

    const user = await User.findById(req.userId);
    if (!user?.twoFA?.tempSecretEnc)
      return res
        .status(400)
        .json({ success: false, error: "No setup in progress" });

    const base32 = decrypt(user.twoFA.tempSecretEnc);
    const ok = speakeasy.totp.verify({
      secret: base32,
      encoding: "base32",
      token,
      window: 1,
    });
    if (!ok)
      return res.status(400).json({ success: false, error: "Invalid OTP" });

    // finalize
    user.twoFA.secretEnc = encrypt(base32);
    user.twoFA.enabled = true;
    user.twoFA.tempSecretEnc = null;

    // create backup codes (show once)
    const codes = Array.from(
      { length: 8 },
      () => require("crypto").randomBytes(4).toString("hex") // 8 hex chars
    );
    user.twoFA.backupCodes = await Promise.all(codes.map(hashString));

    await user.save();

    // Issue FINAL auth token now (already MFA-verified)
    const finalToken = jwt.sign(
      { id: user._id, username: user.username, mfa: true, role: user?.role },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({
      success: true,
      message: "2FA enabled",
      backupCodes: codes, // <-- show once on UI, ask to store securely
      token: finalToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
      },
    });
  } catch (e) {
    console.error("2FA verify-setup error:", e);
    res
      .status(500)
      .json({ success: false, error: "Failed to verify 2FA setup" });
  }
});

// --- 3) MFA login step (after /auth/login returns mfa_token) ---
router.post("/login", otpLimiter, requireMfaStageToken, async (req, res) => {
  try {
    const { otp, backupCode } = req.body;
    const user = await User.findById(req.userId);
    if (!user?.twoFA?.enabled)
      return res.status(400).json({ success: false, error: "2FA not enabled" });

    let ok = false;

    // Prefer OTP
    if (otp) {
      const base32 = decrypt(user.twoFA.secretEnc);
      ok = speakeasy.totp.verify({
        secret: base32,
        encoding: "base32",
        token: otp,
        window: 1,
      });
    }

    // Or accept a backup code (one-time)
    if (!ok && backupCode) {
      const idx = await (async () => {
        for (let i = 0; i < (user.twoFA.backupCodes || []).length; i++) {
          if (await compareHash(backupCode, user.twoFA.backupCodes[i]))
            return i;
        }
        return -1;
      })();
      if (idx >= 0) {
        ok = true;
        user.twoFA.backupCodes.splice(idx, 1); // consume code
        await user.save();
      }
    }

    if (!ok)
      return res
        .status(400)
        .json({ success: false, error: "Invalid OTP or backup code" });

    // Issue FINAL auth token
    const token = jwt.sign(
      { id: user._id, username: user.username, mfa: true, role: user?.role },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({
      success: true,
      message: "MFA verified",
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
      },
    });
  } catch (e) {
    console.error("MFA login error", e);
    res.status(500).json({ success: false, error: "MFA login failed" });
  }
});

module.exports = router;
