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


const TVAccessRequest = require("./models/tvAccess");
const TVAccessSession = require("./models/tvAccessSession");
const requireRole = require("./middlewares/roles");

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

app.get("/admin/requests", authenticateToken, requireRole("admin", "superadmin"), async (req, res) => {
  const requests = await TVAccessRequest.find({ status: "pending" }).populate("userId", "username email fullName");
  res.json({ success: true, requests });
});


app.post("/admin/handle-request/:requestId", authenticateToken, requireRole("admin", "superadmin"), async (req, res) => {
  const { approve, message } = req.body;
  const request = await TVAccessRequest.findById(req.params.requestId);

  if (!request) return res.status(404).json({ success: false, error: "Request not found" });
  if (request.status !== "pending") return res.status(400).json({ success: false, error: "Already handled" });

  request.status = approve ? "approved" : "rejected";
  request.messageFromAdmin = message || "";
  await request.save();

  if (approve) {
    const expiresAt = new Date(Date.now() + 3 * 60 * 60 * 1000); // 3 hrs
    const session = new TVAccessSession({ userId: request.userId, expiresAt });
    await session.save();
  }

  res.json({ success: true, message: `Request ${approve ? "approved" : "rejected"}` });
});





app.post("/admin/request-verification/:requestId", authenticateToken, requireRole("superadmin"), async (req, res) => {
  const { message } = req.body;
  const request = await TVAccessRequest.findById(req.params.requestId);

  if (!request) return res.status(404).json({ success: false, error: "Request not found" });

  request.status = "verification";
  request.messageFromAdmin = message || "Need additional verification";
  await request.save();

  res.json({ success: true, message: "Verification requested from user" });
});


// Node.js (Express example)
app.get("/api/getlink", authenticateToken, requireRole("user", "superadmin", "admin"), async (req, res) => {
  const { CHID } = req.query;
  try {
    const user = await User.findById(req.user.id);
    if (!user)
      return res.status(404).json({ success: false, error: "User not found" });


    if (req?.user?.role === "superadmin") {

      if (req?.user?.role !== user?.role && user?.role !== "superadmin") {
        return res.status(403).json({ success: false, redirect: true, error: "Session Mismatched!!", reditectTo: "/session-mismatched" });
      }
      const responsee = await fetch(
        `https://www.techjail.net/aamshd/huritv9/getlink.php?vv=1&CHID=${CHID}`
      );
      const dataa = await responsee.text();
      return res.send(dataa);
    }
    const session = await TVAccessSession.findOne({ userId: req.user.id });

    if (!session || session.expiresAt < new Date()) {
      return res.status(403).json({ success: false, error: "TV access expired or not granted" });
    }
    const response = await fetch(
      `https://www.techjail.net/aamshd/huritv9/getlink.php?vv=1&CHID=${CHID}`
    );
    const data = await response.text();
    res.send(data);

  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to fetch user" });
  }
});

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

app.use("/streams", express.static(path.join(__dirname, "streams")));

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
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      fullName,
    });
    await newUser.save();

    const token = jwt.sign({ id: newUser._id, username }, JWT_SECRET, {
      expiresIn: "30d",
    });
    res.json({
      success: true,
      message: "User registered",
      token,
      user: { id: newUser._id, username, email, fullName, role: newUser?.role },
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ success: false, error: "Registration failed" });
  }
});
// Login route
app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({
      $or: [{ username }, { email: username }],
    });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res
        .status(401)
        .json({ success: false, error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user?.fullName,
        role: user?.role
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, error: "Login failed" });
  }
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

    jwt.verify(token, JWT_SECRET, (err, us) => {
      if (err) {
        console.error("JWT verification failed:", err);
        return res.status(403).json({ error: "Invalid token" });
      }
      user = us;
    });

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

    jwt.verify(token, JWT_SECRET, (err, us) => {
      if (err) return res.sendStatus(403);
      user = us;
    });

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

// Get current user info
app.get("/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user)
      return res.status(404).json({ success: false, error: "User not found" });
    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user?.role,
        createdAt: user.createdAt,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to fetch user" });
  }
});

// 🎬 MOVIES

app.get("/proxy/hydra", async (req, res) => {
  const { t, i } = req.query;
  if (!t) return res.status(400).json({ success: false, error: "Missing TMDB ID (?t=)" });

  try {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();

    // Go to the main movie page first to get cookies & session
    const movieUrl = "https://hydrahd.sh/movie/194010-watch-the-old-guard-2-2025-online";
    await page.goto(movieUrl, { waitUntil: "networkidle2" });

    // Evaluate fetch within the page context to get the API content
    const html = await page.evaluate(async (i, t) => {
      const response = await fetch(`/ajax/mov_0.php?i=${i}&t=${t}`, {
        headers: { "X-Requested-With": "XMLHttpRequest" }
      });
      return await response.text();
    }, i, t);

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
        "sec-ch-ua":
          '"Not)A;Brand";v="8", "Chromium";v="138", "Brave";v="138"',
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

app.post("/tv/request-access", authenticateToken, requireRole("user"), async (req, res) => {
  const existingRequest = await TVAccessRequest.findOne({ userId: req.user.id, status: "pending" });
  if (existingRequest) return res.status(400).json({ success: false, error: "You already have a pending request" });

  const expiresAt = new Date(Date.now() + 60 * 1000); // 1 min

  const request = new TVAccessRequest({
    userId: req.user.id,
    reason: req.body.reason || "",
    expiresAt,
  });

  await request.save();
  res.json({ success: true, message: "Request submitted" });
});


app.get("/tv/access-status", authenticateToken, requireRole("user", "admin", "superadmin"), async (req, res) => {
  if (req?.user?.role === "superadmin") {
    return res.json({ success: true, status: "approved", expiresAt: new Date(Date.now() + 3 * 60 * 60 * 1000) });
  }
  const session = await TVAccessSession.findOne({ userId: req.user.id });
  if (session && session.expiresAt > new Date()) {
    return res.json({ success: true, status: "approved", expiresAt: session.expiresAt });
  }


  const latestRequest = await TVAccessRequest.findOne({ userId: req.user.id }).sort({ createdAt: -1 });

  if (!latestRequest) return res.json({ success: true, status: "no-request" });

  res.json({
    success: true,
    status: latestRequest.status,
    message: latestRequest.messageFromAdmin || null,
  });
});



app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Proxy server running at http://localhost:${PORT}`);
});
