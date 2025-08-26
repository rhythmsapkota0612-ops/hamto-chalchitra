const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const User = require("./models/user");
const authenticateToken = require("./middlewares/authenticate");
const StreamHistory = require("./models/streamHistory");
const multer = require("multer");
const puppeteer = require("puppeteer");
const geoip = require("geoip-lite");
const countries = require("i18n-iso-countries");
const TVAccessRequest = require("./models/tvAccess");
const TVAccessSession = require("./models/tvAccessSession");
const requireRole = require("./middlewares/roles");

const Session = require("./models/session");

const adminRoutes = require("./routes/admin"); // <- path to the file above

// Configure multer for handling FormData
const upload = multer();

const uploadV2 = multer({ dest: "tmp/" });

// Import node-fetch for CommonJS
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());
// app.set('trust proxy', true);

// JWT Secret (in production, use environment variable)
const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";

// 🔐 AUTHENTICATION ROUTES
// Connect to MongoDB Atlas
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

//Testing

app.get(
  "/admin/requests",
  authenticateToken,
  requireRole("admin", "superadmin"),
  async (req, res) => {
    const requests = await TVAccessRequest.find({ status: "pending" }).populate(
      "userId",
      "username email fullName"
    );
    res.json({ success: true, requests });
  }
);

app.post(
  "/admin/handle-request/:requestId",
  authenticateToken,
  requireRole("admin", "superadmin"),
  async (req, res) => {
    const { approve, message } = req.body;
    const request = await TVAccessRequest.findById(req.params.requestId);

    if (!request)
      return res
        .status(404)
        .json({ success: false, error: "Request not found" });
    if (request.status !== "pending")
      return res.status(400).json({ success: false, error: "Already handled" });

    request.status = approve ? "approved" : "rejected";
    request.messageFromAdmin = message || "";
    await request.save();

    if (approve) {
      const expiresAt = new Date(Date.now() + 3 * 60 * 60 * 1000); // 3 hrs
      const session = new TVAccessSession({
        userId: request.userId,
        expiresAt,
      });
      await session.save();
    }

    res.json({
      success: true,
      message: `Request ${approve ? "approved" : "rejected"}`,
    });
  }
);

app.post(
  "/admin/request-verification/:requestId",
  authenticateToken,
  requireRole("superadmin"),
  async (req, res) => {
    const { message } = req.body;
    const request = await TVAccessRequest.findById(req.params.requestId);

    if (!request)
      return res
        .status(404)
        .json({ success: false, error: "Request not found" });

    request.status = "verification";
    request.messageFromAdmin = message || "Need additional verification";
    await request.save();

    res.json({ success: true, message: "Verification requested from user" });
  }
);

function isStreamUrl(url) {
  try {
    const parsed = new URL(url);
    // Allow only known safe video domains
    return !!parsed;
  } catch {
    return false;
  }
}

const TARGET_API_BASE = "https://livesport.su";

// 2FA enforcement flags
const ENFORCE_2FA = true; // mandatory 2FA
const MFA_TOKEN_TTL = process.env.MFA_TOKEN_TTL || "5m";

const twoFARoutes = require("./routes/auth-2fa");
app.use("/auth/2fa", twoFARoutes);

app.get("/proxy/iframe", async (req, res) => {
  const targetUrl = decodeURIComponent(req.query.url);

  // Only allow video player URLs
  if (!isStreamUrl(targetUrl)) {
    return res.status(403).send("Blocked");
  }

  // Set CORS headers to allow iframe embedding
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  );
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  try {
    const response = await fetch(targetUrl, {
      headers: {
        Origin: "https://livesport.su", // Use the actual origin
        Referer: "https://livesport.su/",
        "User-Agent":
          req.headers["user-agent"] ||
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        Connection: "keep-alive",
        "Upgrade-Insecure-Requests": "1",
      },
    });

    if (!response.ok) {
      return res
        .status(response.status)
        .send(`Error: ${response.status} ${response.statusText}`);
    }

    const contentType = response.headers.get("content-type") || "text/html";
    res.setHeader("Content-Type", contentType);

    // Don't set X-Frame-Options to allow iframe embedding
    res.removeHeader("X-Frame-Options");

    let html = await response.text();

    // Remove specific ad-related scripts while preserving video player scripts
    html = html
      // Remove scripts containing ad-related keywords
      .replace(
        /<script[^>]*>[\s\S]*?(popup|adcash|advertisement|adsystem|googlesyndication|doubleclick|amazon-adsystem|outbrain|taboola|_pop|popunder|redirect)[\s\S]*?<\/script>/gi,
        ""
      )

      // Remove scripts that contain common ad patterns
      .replace(
        /<script[^>]*>[\s\S]*?(window\.open|location\.href\s*=|location\.replace|document\.write.*(?:ad|popup))[\s\S]*?<\/script>/gi,
        ""
      )

      // Remove external ad scripts by src
      .replace(
        /<script[^>]*src=["'][^"']*(?:ads|advertisement|popup|redirect|banner)[^"']*["'][^>]*><\/script>/gi,
        ""
      )
      .replace(
        /<a[^>]*href=["'][^"']*(?:ttonyfiiyajkh)[^"']*["'][^>]*><\/a>/gi,
        ""
      )
      // Remove div containers commonly used for ads - but replace with empty divs to prevent JS errors
      .replace(
        /<div[^>]*(?:class|id)=["'][^"']*(?:ad|advertisement|popup|banner|overlay)[^"']*["'][^>]*>[\s\S]*?<\/div>/gi,
        '<div style="display:none;"></div>'
      )

      // Remove inline event handlers that could trigger popups
      .replace(
        /on(click|load|mouseover|mouseout|focus|blur)\s*=\s*["'][^"']*(?:window\.open|popup|redirect)[^"']*["']/gi,
        ""
      )

      // Remove specific popup patterns in inline JS
      .replace(/onclick\s*=\s*["'][^"']*window\.open[^"']*["']/gi, "")

      // Remove meta refresh redirects
      .replace(/<meta[^>]*http-equiv=["']refresh["'][^>]*>/gi, "")

      // Remove X-Frame-Options and CSP meta tags that block iframe embedding
      .replace(
        /<meta[^>]*http-equiv=["'](X-Frame-Options|Content-Security-Policy)["'][^>]*>/gi,
        ""
      )

      // Replace common ad container divs with empty divs to prevent JS errors
      .replace(
        /<div[^>]*(?:class|id)=["'][^"']*(?:popup|advertisement|modal|overlay)[^"']*["'][^>]*>[\s\S]*?<\/div>/gi,
        '<div style="display:none;"></div>'
      )

      // Remove noscript tags (often contain ad fallbacks)
      .replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, "");

    // Inject script to intercept and proxy all requests + add error handling
    const proxyScript = `
      <script>
        (function() {
          // Add error handling for missing DOM elements
          const originalQuerySelector = document.querySelector;
          const originalQuerySelectorAll = document.querySelectorAll;
          const originalGetElementById = document.getElementById;
          const originalGetElementsByClassName = document.getElementsByClassName;
          
          // Override querySelector to return dummy elements for ad-related selectors
          document.querySelector = function(selector) {
            const result = originalQuerySelector.call(this, selector);
            if (!result && (selector.includes('ad') || selector.includes('popup') || selector.includes('overlay'))) {
              // Return a dummy element to prevent null errors
              const dummyElement = document.createElement('div');
              dummyElement.style.display = 'none';
              dummyElement.remove = function() {}; // Prevent errors when trying to remove
              dummyElement.style.visibility = 'hidden';
              return dummyElement;
            }
            return result;
          };
          
          document.getElementById = function(id) {
            const result = originalGetElementById.call(this, id);
            if (!result && (id.includes('ad') || id.includes('popup') || id.includes('overlay'))) {
              const dummyElement = document.createElement('div');
              dummyElement.style.display = 'none';
              dummyElement.remove = function() {};
              dummyElement.id = id;
              return dummyElement;
            }
            return result;
          };
          
          // Override global error handler to suppress ad-related errors
          const originalError = window.onerror;
          window.onerror = function(message, source, lineno, colno, error) {
            if (message && (
              message.includes("Cannot read properties of null (reading 'remove')") ||
              message.includes("Cannot read properties of undefined") ||
              message.includes("popup") || 
              message.includes("advertisement")
            )) {
              console.log('Suppressed ad-related error:', message);
              return true; // Prevent error from showing
            }
            if (originalError) {
              return originalError.apply(this, arguments);
            }
            return false;
          };
          
          const PROXY_URL = 'http://localhost:3001/proxy/api?url=';
          const TARGET_DOMAIN = 'livesport.su';
          
          // Override fetch to proxy ALL external requests
          const originalFetch = window.fetch;
          window.fetch = function(url, options = {}) {
            const fullUrl = url.startsWith('/') ? 'https://' + TARGET_DOMAIN + url : url;
            
            if (fullUrl.includes(TARGET_DOMAIN) || url.startsWith('/api') || url.startsWith('/cdn-cgi')) {
              console.log('Proxying fetch:', fullUrl);
              const proxyUrl = PROXY_URL + encodeURIComponent(fullUrl);
              return originalFetch(proxyUrl, {
                ...options,
                mode: 'cors',
                credentials: 'omit'
              });
            }
            return originalFetch(url, options);
          };

          // Override XMLHttpRequest completely
          const OriginalXHR = window.XMLHttpRequest;
          window.XMLHttpRequest = function() {
            const xhr = new OriginalXHR();
            const originalOpen = xhr.open;
            
            xhr.open = function(method, url, async = true, user, password) {
              const fullUrl = url.startsWith('/') ? 'https://' + TARGET_DOMAIN + url : url;
              
              if (fullUrl.includes(TARGET_DOMAIN) || url.startsWith('/api') || url.startsWith('/cdn-cgi')) {
                console.log('Proxying XHR:', fullUrl);
                const proxyUrl = PROXY_URL + encodeURIComponent(fullUrl);
                return originalOpen.call(this, method, proxyUrl, async, user, password);
              }
              return originalOpen.call(this, method, url, async, user, password);
            };
            
            return xhr;
          };
          
          // Block direct external requests in case any slip through
          const originalCreateElement = document.createElement;
          document.createElement = function(tagName) {
            const element = originalCreateElement.call(this, tagName);
            
            if (tagName.toLowerCase() === 'script') {
              const originalSetAttribute = element.setAttribute;
              element.setAttribute = function(name, value) {
                if (name === 'src' && value.includes(TARGET_DOMAIN)) {
                  console.log('Blocking external script:', value);
                  return; // Block external scripts
                }
                return originalSetAttribute.call(this, name, value);
              };
            }
            
            return element;
          };
          
          console.log('Proxy interceptors and error handlers installed');
        })();
      </script>
    `;

    // Add CSS to hide common ad elements
    const adBlockCSS = `
      <style>
        /* Hide common ad containers */
        [class*="ad"], [class*="popup"], [class*="overlay"], [class*="banner"],
        [id*="ad"], [id*="popup"], [id*="overlay"], [id*="banner"],
        .advertisement, .popup-overlay, .modal-overlay, .ad-container {
          display: none !important;
          visibility: hidden !important;
        }
        
        /* Ensure video containers remain visible */
        [class*="video"], [class*="player"], [id*="video"], [id*="player"],
        video, .video-container, .player-container {
          display: block !important;
          visibility: visible !important;
        }
        
        /* Hide common popup elements */
        .popup, .modal, .overlay, .advertisement {
          display: none !important;
        }
      </style>
    `;

    // Insert proxy script and CSS into head or before closing body tag
    if (html.includes("</head>")) {
      html = html.replace("</head>", `${proxyScript}${adBlockCSS}</head>`);
    } else if (html.includes("<head>")) {
      html = html.replace("<head>", `<head>${proxyScript}${adBlockCSS}`);
    } else if (html.includes("</body>")) {
      html = html.replace("</body>", `${proxyScript}${adBlockCSS}</body>`);
    } else {
      html = proxyScript + adBlockCSS + html;
    }

    res.send(html);
  } catch (e) {
    console.error("Proxy error:", e);
    res.status(500).send("Proxy error: " + e.message);
  }
});

// Handle OPTIONS preflight requests
app.options("/proxy/iframe", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  );
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.status(200).send();
});

// API proxy route for intercepted requests
app.all("/proxy/api", async (req, res) => {
  const targetUrl = decodeURIComponent(req.query.url);

  // Set CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Requested-With"
  );

  if (req.method === "OPTIONS") {
    return res.status(200).send();
  }

  try {
    const fetchOptions = {
      method: req.method,
      headers: {
        Origin: "https://livesport.su",
        Referer: "https://livesport.su/",
        "User-Agent":
          req.headers["user-agent"] ||
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        Accept: req.headers.accept || "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.5",
        Connection: "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
      },
    };

    // Add body for POST requests
    if (req.method === "POST" && req.body) {
      fetchOptions.body = JSON.stringify(req.body);
      fetchOptions.headers["Content-Type"] = "application/json";
    }

    const response = await fetch(targetUrl, fetchOptions);

    if (!response.ok) {
      return res
        .status(response.status)
        .json({ error: `${response.status} ${response.statusText}` });
    }

    const contentType =
      response.headers.get("content-type") || "application/json";
    res.setHeader("Content-Type", contentType);

    if (contentType.includes("application/json")) {
      const data = await response.json();
      res.json(data);
    } else {
      const text = await response.text();
      res.send(text);
    }
  } catch (e) {
    console.error("API Proxy error for", targetUrl, ":", e);
    res.status(500).json({ error: "Proxy error: " + e.message });
  }
});

app.options("/proxy/api", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Requested-With"
  );
  res.status(200).send();
});

app.get("/proxy/live-sport", async (req, res) => {
  const urlPath = req.query.url;

  if (!urlPath || !urlPath.startsWith("/api")) {
    return res.status(400).json({
      error: "Missing or invalid url query parameter. It must start with /api",
    });
  }

  try {
    const targetUrl = `${TARGET_API_BASE}${urlPath}`;
    const response = await fetch(targetUrl);

    if (!response.ok) {
      return res.status(response.status).json({ error: "Upstream error" });
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error("Proxy error:", error);
    res.status(500).json({ error: "Internal server error (proxy)" });
  }
});

// Node.js (Express example)
app.get(
  "/api/getlink",
  authenticateToken,
  requireRole("user", "superadmin", "admin"),
  async (req, res) => {
    const { CHID } = req.query;
    try {
      const user = await User.findById(req.user.id);
      if (!user)
        return res
          .status(404)
          .json({ success: false, error: "User not found" });

      if (req?.user?.role === "superadmin") {
        if (req?.user?.role !== user?.role && user?.role !== "superadmin") {
          return res.status(403).json({
            success: false,
            redirect: true,
            error: "Session Mismatched!!",
            reditectTo: "/session-mismatched",
          });
        }
        const responsee = await fetch(
          `https://www.techjail.net/aamshd/huritv9/getlink.php?vv=1&CHID=${CHID}`
        );
        const dataa = await responsee.text();
        return res.send(dataa);
      }

      if (req?.user?.role === "admin") {
        if (req?.user?.role !== user?.role && user?.role !== "admin") {
          return res.status(403).json({
            success: false,
            redirect: true,
            error: "Session Mismatched!!",
            reditectTo: "/session-mismatched",
          });
        }
        const responsee = await fetch(
          `https://www.techjail.net/aamshd/huritv9/getlink.php?vv=1&CHID=${CHID}`
        );
        const dataa = await responsee.text();
        return res.send(dataa);
      }
      const session = await TVAccessSession.findOne({ userId: req.user.id });

      if (!session || session.expiresAt < new Date()) {
        return res
          .status(403)
          .json({ success: false, error: "TV access expired or not granted" });
      }
      const response = await fetch(
        `https://www.techjail.net/aamshd/huritv9/getlink.php?vv=1&CHID=${CHID}`
      );
      const data = await response.text();
      res.send(data);
    } catch (err) {
      res.status(500).json({ success: false, error: "Failed to fetch user" });
    }
  }
);

app.post("/api/upload-chunk", uploadV2.single("file"), (req, res) => {
  const { streamId, fileName } = req.body;
  const tempPath = req.file?.path;

  if (!streamId || !fileName || !tempPath) {
    return res
      .status(400)
      .json({ success: false, message: "Missing streamId, fileName, or file" });
  }

  const streamDir = path.join(__dirname, "streams", streamId);
  if (!fs.existsSync(streamDir)) {
    fs.mkdirSync(streamDir, { recursive: true });
  }

  const finalPath = path.join(streamDir, fileName);

  fs.rename(tempPath, finalPath, async (err) => {
    if (err) {
      console.error("❌ Error saving chunk:", err);
      return res
        .status(500)
        .json({ success: false, message: "Failed to save file" });
    }

    console.log(`✅ Saved: /streams/${streamId}/${fileName}`);

    // 🔁 CLEANUP: Delete old .ts files if more than 10 (excluding playlist.m3u8)
    try {
      const files = fs
        .readdirSync(streamDir)
        .filter((file) => file.endsWith(".ts"))
        .map((file) => ({
          name: file,
          time: fs.statSync(path.join(streamDir, file)).mtime.getTime(),
        }))
        .sort((a, b) => a.time - b.time); // oldest first

      const maxChunks = 10;
      if (files.length > maxChunks) {
        const toDelete = files.slice(0, files.length - maxChunks);
        for (const file of toDelete) {
          const filePath = path.join(streamDir, file.name);
          fs.unlinkSync(filePath);
          console.log(`🗑️ Deleted old chunk: ${file.name}`);
        }
      }
    } catch (cleanupErr) {
      console.warn("⚠️ Cleanup error:", cleanupErr.message);
    }

    return res.status(200).json({
      success: true,
      streamUrl: `${req.protocol}://${req.get(
        "host"
      )}/streams/${streamId}/stream.m3u8`,
    });
  });
});

const PasswordResetToken = require("./models/password-reset");
const { sendPasswordReset } = require("./utils/mailer");
const rateLimit = require("express-rate-limit");

const forgotLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

app.post("/auth/forgot-password", forgotLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email)
    return res.status(400).json({ success: false, error: "Email required" });

  const user = await User.findOne({ email });
  // Always respond ok to avoid user enumeration
  if (!user)
    return res.json({
      success: true,
      message: "If that email exists, you'll receive a link shortly.",
    });

  const raw = crypto.randomBytes(24).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(raw).digest("hex");
  const ttlMin = Number(process.env.PASSWORD_RESET_TTL_MIN || 30);
  const expiresAt = new Date(Date.now() + ttlMin * 60 * 1000);

  await PasswordResetToken.create({ userId: user._id, tokenHash, expiresAt });

  const link = `${
    process.env.RESET_URL_BASE
  }?token=${raw}&uid=${user._id.toString()}`;
  try {
    await sendPasswordReset(user.email, link);
  } catch (e) {
    /* log but don't leak */
  }

  res.json({
    success: true,
    message: "If that email exists, you'll receive a link shortly.",
  });
});

app.post("/auth/reset-password", async (req, res) => {
  const { uid, token, newPassword } = req.body;
  if (!uid || !token || !newPassword) {
    return res
      .status(400)
      .json({ success: false, error: "uid, token, newPassword required" });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({
      success: false,
      error: "Password must be at least 6 characters",
    });
  }

  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const entry = await PasswordResetToken.findOne({
    userId: uid,
    tokenHash,
  }).sort({ createdAt: -1 });
  if (!entry || entry.usedAt || entry.expiresAt < new Date()) {
    return res
      .status(400)
      .json({ success: false, error: "Invalid or expired token" });
  }

  const user = await User.findById(uid);
  if (!user)
    return res.status(404).json({ success: false, error: "User not found" });

  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();

  entry.usedAt = new Date();
  await entry.save();

  await Session.updateMany(
    { userId: user._id, revokedAt: null },
    { $set: { revokedAt: new Date() } }
  );

  res.json({ success: true, message: "Password updated. Please login again." });
});

app.post("/auth/logout", authenticateToken, async (req, res) => {
  try {
    const sid = req.session?.id;
    if (!sid) {
      return res
        .status(400)
        .json({ success: false, error: "No active session" });
    }

    const s = await Session.findById(sid);
    if (!s) {
      // Session already missing; treat as logged out
      return res.json({ success: true, message: "Logged out" });
    }
    if (s.revokedAt) {
      return res.json({ success: true, message: "Already logged out" });
    }

    s.revokedAt = new Date();
    await s.save();
    return res.json({ success: true, message: "Logged out" });
  } catch (e) {
    console.error("POST /auth/logout error:", e);
    return res.status(500).json({ success: false, error: "Logout failed" });
  }
});

app.use("/streams", express.static(path.join(__dirname, "streams")));

app.use("/admin", adminRoutes);

app.get("/api/ping", (req, res) => res.send("pong"));

app.get("/fetch-html", async (req, res) => {
  const targetUrl = "https://www.techjail.net/aamshd/v9x9/";

  if (!targetUrl) {
    return res.status(400).send('Missing "url" query parameter');
  }

  try {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();

    await page.goto(targetUrl, { waitUntil: "networkidle2" });
    const html = await page.content();

    await browser.close();

    res.send(html);
  } catch (error) {
    console.error("Error fetching HTML:", error);
    res.status(500).send("Failed to fetch HTML");
  }
});
// Add near the top
const watchPartyRoutes = require("./routes/watch-party");

// After app.use(cors())
app.use("/watchparty", watchPartyRoutes);
app.use("/live", express.static(path.join(__dirname, "public", "live")));

// Register route
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, password, fullName } = req.body;
    if (!username || !email || !password || !fullName)
      return res
        .status(400)
        .json({ success: false, error: "All fields required" });
    if (password.length < 6)
      return res.status(400).json({
        success: false,
        error: "Password must be at least 6 characters",
      });

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser)
      return res
        .status(409)
        .json({ success: false, error: "Username or email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      username,
      email,
      password: hashedPassword,
      fullName,
    });

    if (ENFORCE_2FA) {
      // Only allow setup step
      const mfa_token = jwt.sign(
        { sub: newUser._id.toString(), stage: "setup" },
        JWT_SECRET,
        { expiresIn: MFA_TOKEN_TTL }
      );
      return res.status(201).json({
        success: true,
        message: "Account created. 2FA setup required.",
        mfa_setup_required: true,
        mfa_token,
      });
    }

    // (Not used when mandatory, but kept for completeness)
    const token = jwt.sign(
      { id: newUser._id, username, role: newUser?.role },
      JWT_SECRET,
      {
        expiresIn: "30d",
      }
    );
    res.json({
      success: true,
      message: "User registered",
      token,
      user: { id: newUser._id, username, email, fullName, role: newUser.role },
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ success: false, error: "Registration failed" });
  }
});

// Login route
// password stage
// BEFORE MFA step: warn if max devices would be exceeded
app.post("/auth/login", async (req, res) => {
  try {
    const { username, password, force } = req.body;
    const user = await User.findOne({
      $or: [{ username }, { email: username }],
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res
        .status(401)
        .json({ success: false, error: "Invalid credentials" });
    }

    // 2FA mandatory?
    if (ENFORCE_2FA && !user.twoFA?.enabled) {
      const mfa_token = jwt.sign(
        { sub: user._id.toString(), stage: "setup" },
        JWT_SECRET,
        {
          expiresIn: MFA_TOKEN_TTL,
        }
      );
      return res.status(403).json({
        success: false,
        need_2fa_setup: true,
        message: "2FA is mandatory. Complete setup to continue.",
        mfa_token,
      });
    }

    // Sessions check
    const max = Math.max(1, user.maxDevices || 1);
    const active = await Session.find({
      userId: user._id,
      revokedAt: null,
    }).sort({ createdAt: 1 });

    // Always issue an MFA token for the next step (login OTP)
    const mfa_token = jwt.sign(
      { sub: user._id.toString(), stage: "mfa" },
      JWT_SECRET,
      {
        expiresIn: MFA_TOKEN_TTL,
      }
    );

    // If at limit and user hasn't confirmed, send preflight warning
    if (active.length >= max && !force) {
      return res.status(428).json({
        success: false,
        code: "MAX_SESSIONS_REACHED",
        message: `You’ve reached the maximum allowed devices (${max}). Continuing will revoke your oldest session.`,
        requiresSessionRevoke: true,
        mfa_required: true,
        mfa_token, // FE will keep this and, if user confirms, proceed to OTP
        activeSessions: active.map((s) => ({
          id: s._id.toString(),
          deviceId: s.deviceId,
          createdAt: s.createdAt,
          lastSeenAt: s.lastSeenAt,
        })),
        maxDevices: max,
      });
    }

    // Otherwise proceed to MFA verification step
    return res.status(200).json({
      success: true,
      mfa_required: true,
      mfa_token,
      willRevokeOnSuccess: active.length >= max, // FYI flag for FE (optional)
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, error: "Login failed" });
  }
});

app.get("/region", async (req, res) => {
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
  const geo = geoip.lookup(ip);
  countries.registerLocale(require("i18n-iso-countries/langs/en.json"));
  const countryName = countries.getName(geo?.country, "en");
  return res.status(200).json({
    success: true,
    data: {
      message: `Successfully configured ip`,
      data: { ...geo, ip, countryName: countryName },
    },
  });
});

app.get("/history/stream", authenticateToken, async (req, res) => {
  try {
    const { streamType, isCompleted } = req.query;
    const userId =
      typeof req.user.id === "string" &&
      mongoose.Types.ObjectId.isValid(req.user.id)
        ? new mongoose.Types.ObjectId(req.user.id)
        : undefined;

    if (!userId) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const matchStage = {
      userId,
    };

    if (streamType) matchStage.streamType = streamType;
    if (isCompleted !== undefined)
      matchStage.isCompleted = isCompleted === "true";

    const history = await StreamHistory.aggregate([
      { $match: matchStage },
      { $sort: { watchedAt: -1 } },
      {
        $group: {
          _id: "$tmdbId",
          doc: { $first: "$$ROOT" },
        },
      },
      { $replaceRoot: { newRoot: "$doc" } },
      { $sort: { watchedAt: -1 } },
    ]);

    res.status(200).json({ history });
  } catch (err) {
    console.error("Error fetching stream history:", err);
    res.status(500).json({ error: "Failed to fetch stream history" });
  }
});

app.get("/history/stream/:tmdbId", authenticateToken, async (req, res) => {
  try {
    const { tmdbId } = req.params;
    const { streamType = "movie" } = req.query;

    if (!tmdbId) {
      return res.status(400).json({ error: "tmdbId is required" });
    }

    const history = await StreamHistory.findOne({
      userId: req.user.id,
      tmdbId: Number(tmdbId),
      streamType,
    }).sort({ watchedAt: -1 }); // Get the most recent one

    if (!history) {
      return res.status(404).json({ error: "History not found" });
    }

    res.status(200).json({
      progress: history.progress || 0,
      duration: history.duration || 0,
      episode: history.episode,
      season: history.season,
      watchedAt: history.watchedAt,
    });
  } catch (err) {
    console.error("Error fetching stream resume history:", err);
    res.status(500).json({ error: "Failed to fetch stream history" });
  }
});

app.post("/history/stream", upload.none(), async (req, res) => {
  try {
    let requestData;

    // Handle both JSON and FormData
    if (req.body.data) {
      // FormData from sendBeacon
      requestData = JSON.parse(req.body.data);
    } else {
      // Direct JSON
      requestData = req.body;
    }

    const {
      tmdbId,
      title,
      imdbId,
      watchedAt,
      streamType,
      episode,
      posterUrl,
      progress,
      season,
      token,
      duration,
      backDropUrl,
    } = requestData;

    // ✅ Validate required fields
    if (!tmdbId || !title || !streamType) {
      return res
        .status(400)
        .json({ error: "tmdbId, title, and streamType are required" });
    }

    if (!["movie", "tv"].includes(streamType)) {
      return res
        .status(400)
        .json({ error: "streamType must be either 'movie' or 'tv'" });
    }

    if (streamType === "tv" && !episode) {
      return res
        .status(400)
        .json({ error: "episode is required for TV stream type" });
    }

    if (!token) {
      return res.status(401).json({ error: "Token is required" });
    }

    let user;

    const { validateFinalTokenAndSession } = require("./utils/auth");
    let payload;
    try {
      ({ payload } = await validateFinalTokenAndSession(token));
    } catch {
      return res.status(403).json({ error: "Invalid token/session" });
    }
    user = payload;

    if (!user) {
      return res.status(403).json({ error: "Invalid token" });
    }

    const query = {
      userId: user.id,
      tmdbId,
      imdbId,
      ...(streamType === "tv" ? { episode } : {}),
    };

    const updateData = {
      title,
      streamType,
      posterUrl,
      progressPercentage:
        progress && duration ? (progress / duration) * 100 : 0,
      backDropUrl,
      watchedAt: watchedAt || new Date(),
    };

    if (streamType === "tv") {
      updateData.episode = episode;
      updateData.season = season;
    }

    const history = await StreamHistory.findOneAndUpdate(query, updateData, {
      new: true,
      upsert: true,
      setDefaultsOnInsert: true,
    });

    res.status(200).json({ message: "History upserted via POST", history });
  } catch (err) {
    console.error("POST /history/stream error:", err);
    res.status(500).json({ error: "Failed to upsert history" });
  }
});

app.patch("/history/stream", async (req, res) => {
  try {
    const {
      tmdbId,
      title,
      watchedAt,
      imdbId,
      streamType,
      episode,
      posterUrl,
      progress,
      token,
      duration,
      season,
      backDropUrl,
    } = req.body;

    // ✅ Validate required fields
    if (!tmdbId || !title || !streamType) {
      return res
        .status(400)
        .json({ error: "tmdbId, title, and streamType are required" });
    }

    if (!["movie", "tv"].includes(streamType)) {
      return res
        .status(400)
        .json({ error: "streamType must be either 'movie' or 'tv'" });
    }

    if (streamType === "tv" && !episode) {
      return res
        .status(400)
        .json({ error: "episode is required for TV stream type" });
    }

    let user;

    const { validateFinalTokenAndSession } = require("./utils/auth");
    let payload;
    try {
      ({ payload } = await validateFinalTokenAndSession(token));
    } catch {
      return res.status(403).json({ error: "Invalid token/session" });
    }
    user = payload;

    const query = {
      userId: user.id,
      tmdbId,
      imdbId,
      ...(streamType === "tv" ? { episode } : {}),
    };

    const updateData = {
      title,
      streamType,
      posterUrl,
      progressPercentage: (progress / duration) * 100,
      backDropUrl,
      watchedAt: watchedAt || new Date(),
    };

    if (streamType === "tv") {
      updateData.episode = episode;
      updateData.season = season;
    }

    const history = await StreamHistory.findOneAndUpdate(query, updateData, {
      new: true,
      upsert: true,
      setDefaultsOnInsert: true,
    });

    res.status(200).json({ message: "History upserted", history });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to upsert history" });
  }
});

// Get current user info (final token + live session required)
app.get("/auth/me", authenticateToken, async (req, res) => {
  try {
    // authenticateToken should set req.user.id and req.session.{id,deviceId}
    const user = await User.findById(req.user.id).lean();
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    return res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        fullName: user.fullName,
        createdAt: user.createdAt,
        mfaEnabled: !!user.twoFA?.enabled,
        maxDevices: typeof user.maxDevices === "number" ? user.maxDevices : 1,
      },
      // Optional: echo current session info for the client
      session: req.session
        ? { id: req.session.id, deviceId: req.session.deviceId }
        : undefined,
    });
  } catch (err) {
    console.error("GET /auth/me error:", err);
    return res
      .status(500)
      .json({ success: false, error: "Failed to fetch user" });
  }
});

// 🎬 MOVIES

app.get("/proxy/hydra", async (req, res) => {
  const { t, i } = req.query;
  if (!t)
    return res
      .status(400)
      .json({ success: false, error: "Missing TMDB ID (?t=)" });

  try {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();

    // Go to the main movie page first to get cookies & session
    const movieUrl =
      "https://hydrahd.sh/movie/194010-watch-the-old-guard-2-2025-online";
    await page.goto(movieUrl, { waitUntil: "networkidle2" });

    // Evaluate fetch within the page context to get the API content
    const html = await page.evaluate(
      async (i, t) => {
        const response = await fetch(`/ajax/mov_0.php?i=${i}&t=${t}`, {
          headers: { "X-Requested-With": "XMLHttpRequest" },
        });
        return await response.text();
      },
      i,
      t
    );

    await browser.close();

    res.setHeader("Content-Type", "text/html");
    return res.status(200).send(html);
  } catch (error) {
    console.error("Proxy error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to fetch stream from hydrahd.sh",
    });
  }
});

app.use("/api/mal", async (req, res) => {
  try {
    // Build upstream URL (keeps path + query string)
    const upstream =
      "https://api.myanimelist.net/v2" +
      req.originalUrl.replace(/^\/api\/mal/, "");

    // Forward method/body and add the required MAL header
    const resp = await fetch(upstream, {
      method: req.method,
      headers: {
        "X-MAL-CLIENT-ID": process.env.MAL_CLIENT_ID, // set in your env
        Accept: req.get("accept") || "application/json",
        // forward content-type only when present
        ...(req.get("content-type")
          ? { "Content-Type": req.get("content-type") }
          : {}),
      },
      body: ["GET", "HEAD"].includes(req.method)
        ? undefined
        : req.body && JSON.stringify(req.body),
    });

    // Pass through useful headers
    res.status(resp.status);
    for (const [k, v] of resp.headers.entries()) {
      if (
        [
          "content-type",
          "cache-control",
          "expires",
          "last-modified",
          "etag",
        ].includes(k.toLowerCase())
      ) {
        res.setHeader(k, v);
      }
    }

    const text = await resp.text();
    res.send(text);
  } catch (err) {
    console.error(err);
    res.status(502).json({ error: "Upstream fetch failed" });
  }
});

// Handle CORS preflight explicitly (optional, helps with some setups)
// app.options("/api/mal/*", cors());

// 📺 TV SERIES
app.get("/proxy/hydra-tv", async (req, res) => {
  const { i, t, s, e } = req.query;

  if (!t || !s || !e) {
    return res.status(400).json({
      success: false,
      error: "Missing required params (?i=imdbID&t=tmdbID&s=season&e=episode)",
    });
  }

  try {
    const url = `https://hydrahd.sh/ajax/auto_tv.php?i=${i}&t=${t}&s=${s}&e=${e}`;

    const response = await fetch(url, {
      method: "GET",
      headers: {
        accept: "*/*",
        "accept-language": "en-US,en;q=0.7",
        priority: "u=1, i",
        referer: `https://hydrahd.sh/watchseries/untamed-online-free/season/${s}/episode/${e}`,
        "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Brave";v="138"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-gpc": "1",
        "user-agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "x-requested-with": "XMLHttpRequest",
        cookie:
          "PHPSESSID=54bb4mknsko7mc1sl5dnbuvvm3; cf_clearance=BgO5vYrbsklUiGv3pOsBDQ0IoTtObUMBCqb8YpnK6NI-1753123027-1.2.1.1-KFyfVRS6k7gfuHcu1VF_mvx8OxQMWqbuqwBWMNatf_9NSSOQIogbEn2hjTkGTS.2lZYUZpO4bpaoefDwsub0ZfT8d.dWB_XS.M9g4U54lLZ1NiwTPZxqnsAF.Ojdcn3gJMRPkGypF3SUoFkBXgDr5_B6N2pfOVY6eDdqJg1Dq8LiErWH.Lj7lsbc2aTTh8cRzGu_yB.jfhkho.GKEN2utzS6Qm2s21PUhnkF2Pehaho",
      },
    });

    const html = await response.text();
    res.setHeader("Content-Type", "text/html");
    return res.status(200).send(html);
  } catch (error) {
    console.error("TV Proxy error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to fetch TV stream from hydrahd.sh",
    });
  }
});

app.post(
  "/tv/request-access",
  authenticateToken,
  requireRole("user"),
  async (req, res) => {
    const existingRequest = await TVAccessRequest.findOne({
      userId: req.user.id,
      status: "pending",
    });
    if (existingRequest)
      return res
        .status(400)
        .json({ success: false, error: "You already have a pending request" });

    const expiresAt = new Date(Date.now() + 60 * 1000); // 1 min

    const request = new TVAccessRequest({
      userId: req.user.id,
      reason: req.body.reason || "",
      expiresAt,
    });

    await request.save();
    res.json({ success: true, message: "Request submitted" });
  }
);

app.get(
  "/tv/access-status",
  authenticateToken,
  requireRole("user", "admin", "superadmin"),
  async (req, res) => {
    if (req?.user?.role === "superadmin") {
      return res.json({
        success: true,
        status: "approved",
        expiresAt: new Date(Date.now() + 3 * 60 * 60 * 1000),
      });
    }
    if (req?.user?.role === "admin") {
      return res.json({
        success: true,
        status: "approved",
        expiresAt: new Date(Date.now() + 3 * 60 * 60 * 1000),
      });
    }
    const session = await TVAccessSession.findOne({ userId: req.user.id });
    if (session && session.expiresAt > new Date()) {
      return res.json({
        success: true,
        status: "approved",
        expiresAt: session.expiresAt,
      });
    }

    const latestRequest = await TVAccessRequest.findOne({
      userId: req.user.id,
    }).sort({ createdAt: -1 });

    if (!latestRequest)
      return res.json({ success: true, status: "no-request" });

    res.json({
      success: true,
      status: latestRequest.status,
      message: latestRequest.messageFromAdmin || null,
    });
  }
);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Proxy server running at http://localhost:${PORT}`);
});
