function requireAccessWithMFA(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token)
      return res.status(401).json({ success: false, error: "Missing token" });

    const payload = jwt.verify(token, JWT_SECRET);

    // Must be a *final* token (not mfa/setup token) and must include the MFA flag
    if (!payload.id || payload.stage || !payload.mfa)
      return res.status(401).json({ success: false, error: "MFA required" });

    req.userId = payload.id;
    req.userName = payload.username;
    next();
  } catch (e) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
}
