const mongoose = require("mongoose");

const sessionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    deviceId: { type: String, index: true }, // from client header/cookie; fallback random
    userAgent: String,
    ip: String,
    createdAt: { type: Date, default: Date.now },
    lastSeenAt: { type: Date, default: Date.now },
    revokedAt: { type: Date, default: null },
  },
  { timestamps: false }
);

sessionSchema.index({ userId: 1, revokedAt: 1, createdAt: 1 });

module.exports = mongoose.model("Session", sessionSchema);
