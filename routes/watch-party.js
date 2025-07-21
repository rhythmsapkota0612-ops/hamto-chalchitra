const express = require("express");
const path = require("path");
const fs = require("fs");
const { exec } = require("child_process");
const crypto = require("crypto");

const router = express.Router();
const LIVE_DIR = path.join(__dirname, "..", "public", "live");

// Ensure live directory exists
if (!fs.existsSync(LIVE_DIR)) fs.mkdirSync(LIVE_DIR, { recursive: true });

router.post("/stream", async (req, res) => {
  const { inputUrl } = req.body;
  if (!inputUrl) return res.status(400).json({ error: "Missing inputUrl" });

  const partyId = crypto.randomBytes(8).toString("hex");
  const outputDir = path.join(LIVE_DIR, partyId);
  fs.mkdirSync(outputDir, { recursive: true });

  const outputPlaylist = path.join(outputDir, "playlist.m3u8");

  // Correctly formatted headers string (CRLF-separated)
  const headers = [
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Referer: https://nettv.com.np/",
    "Origin: https://nettv.com.np",
    "Accept: */*",
    "Accept-Language: en-US,en;q=0.9",
  ].join("\r\n");

  const cmd = `ffmpeg -re -headers "${headers}" -i "${inputUrl}" -c copy -f hls -hls_time 4 -hls_list_size 6 -hls_flags delete_segments+omit_endlist "${outputPlaylist}"`;

  console.log("Running FFmpeg Command:\n", cmd);

  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      console.error(`[FFmpeg Error]`, err);
      console.error(`[FFmpeg STDERR]`, stderr);
    } else {
      console.log(`[FFmpeg STDOUT]`, stdout);
    }
  });

  return res.json({
    success: true,
    partyId,
    streamUrl: `/live/${partyId}/playlist.m3u8`,
    fullStreamUrl: `${req.protocol}s://${req.get(
      "host"
    )}/live/${partyId}/playlist.m3u8`,
  });
});

module.exports = router;
