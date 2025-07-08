const express = require("express");
const cors = require("cors");

// Import node-fetch for CommonJS
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

// 🎬 MOVIES
app.get("/proxy/hydra", async (req, res) => {
  const { t } = req.query;

  if (!t) {
    return res
      .status(400)
      .json({ success: false, error: "Missing TMDB ID (?t=)" });
  }

  try {
    const hydraUrl = `https://hydrahd.sh/ajax/mov_0.php?t=${t}`;

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

app.listen(PORT, () => {
  console.log(`🚀 Proxy server running at http://localhost:${PORT}`);
});
