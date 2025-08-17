const mongoose = require("mongoose");

const tvAccessSessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  grantedAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
});

tvAccessSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("TVAccessSession", tvAccessSessionSchema);
