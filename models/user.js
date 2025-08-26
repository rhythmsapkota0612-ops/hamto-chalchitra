const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "user" },
  createdAt: { type: Date, default: Date.now },
  fullName: { type: String, required: true },
  maxDevices: { type: Number, default: 1 },
  twoFA: {
    enabled: { type: Boolean, default: false },
    secretEnc: { type: String, default: null },
    tempSecretEnc: { type: String, default: null },
    backupCodes: [{ type: String }],
  },
});

module.exports = mongoose.model("User", userSchema);
