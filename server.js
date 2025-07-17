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
const puppeteer = require("puppeteer")

// Configure multer for handling FormData
const upload = multer();

// Import node-fetch for CommonJS
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

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

// Node.js (Express example)
app.get('/api/getlink', async (req, res) => {
  const { CHID } = req.query;
  const response = await fetch(`https://www.techjail.net/aamshd/huritv9/getlink.php?vv=1&CHID=${CHID}`);
  const data = await response.text();
  console.log(data)
  res.send(data);

});


app.get('/fetch-html', async (req, res) => {
  const targetUrl = "https://www.techjail.net/aamshd/v9x9/";

  if (!targetUrl) {
    return res.status(400).send('Missing "url" query parameter');
  }

  try {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();

    await page.goto(targetUrl, { waitUntil: 'networkidle2' });
    const html = await page.content();

    await browser.close();

    res.send(html);
  } catch (error) {
    console.error('Error fetching HTML:', error);
    res.status(500).send('Failed to fetch HTML');
  }
});

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
      user: { id: newUser._id, username, email, fullName },
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

  if (!t) {
    return res
      .status(400)
      .json({ success: false, error: "Missing TMDB ID (?t=)" });
  }

  try {
    const hydraUrl = `https://hydrahd.sh/ajax/mov_0.php?i=${i}t=${t}`;

    const response = await fetch(hydraUrl, {
      method: "GET",
      headers: {
        accept: "*/*",
        "accept-language": "en-US,en;q=0.9",
        priority: "u=1, i",
        referer:
          "https://hydrahd.sh/movie/194010-watch-the-old-guard-2-2025-online",
        "sec-ch-ua":
          '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "x-requested-with": "XMLHttpRequest",
        cookie:
          "PHPSESSID=d780bd3jul80hqn0uhsbfj5j02; _ga=GA1.1.2122661879.1751959599; _ym_uid=1751959600970057947; _ym_d=1751959600; _ym_isad=2; _ga_FSSR5RWVV3=GS2.1.s1751959598$o1$g1$t1751959946$j60$l0$h0; prefetchAd_9258380=true",
      },
    });

    const html = await response.text();
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
    const url = `https://hydrahd.sh/ajax/tv_0.php?i=${i}&t=${t}&s=${s}&e=${e}`;

    const response = await fetch(url, {
      method: "GET",
      headers: {
        accept: "*/*",
        "accept-language": "en-US,en;q=0.9",
        priority: "u=1, i",
        referer: `https://hydrahd.sh/watchseries/squid-game-online-free/season/${s}/episode/${e}`,
        "sec-ch-ua":
          '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "x-requested-with": "XMLHttpRequest",
        cookie:
          "PHPSESSID=d780bd3jul80hqn0uhsbfj5j02; _ga=GA1.1.2122661879.1751959599; _ym_uid=1751959600970057947; _ym_d=1751959600; _ym_isad=2; prefetchAd_9258380=true; _ga_FSSR5RWVV3=GS2.1.s1751968571$o2$g1$t1751969421$j50$l0$h0",
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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Proxy server running at http://localhost:${PORT}`);
});
