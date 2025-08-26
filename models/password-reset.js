const mongoose = require("mongoose");

const passwordResetTokenSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    tokenHash: { type: String, required: true }, // hash of the raw token
    expiresAt: { type: Date, required: true }, // e.g., now + 30 min
    usedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

passwordResetTokenSchema.index({ userId: 1, expiresAt: 1 });

module.exports = mongoose.model("PasswordResetToken", passwordResetTokenSchema);
