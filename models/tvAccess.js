const mongoose = require("mongoose");

const tvAccessRequestSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    status: { type: String, enum: ["pending", "approved", "rejected", "verification"], default: "pending" },
    reason: String,
    messageFromAdmin: String,
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date,
});

tvAccessRequestSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("TVAccessRequest", tvAccessRequestSchema);
