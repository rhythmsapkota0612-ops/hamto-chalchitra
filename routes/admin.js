const express = require("express");
const mongoose = require("mongoose");
const requireRole = require("../middlewares/roles");
const authenticateToken = require("../middlewares/authenticate");
const User = require("../models/user");
const Session = require("../models/session");

const admin = express.Router();

function isValidId(id) {
  return typeof id === "string" && mongoose.Types.ObjectId.isValid(id);
}

// GET /admin/users?query=...
admin.get(
  "/users",
  authenticateToken,
  requireRole("superadmin"),
  async (req, res) => {
    try {
      const q = (req.query.query || "").trim();
      const filter = q
        ? {
            $or: [
              { username: new RegExp(q, "i") },
              { email: new RegExp(q, "i") },
              { fullName: new RegExp(q, "i") },
            ],
          }
        : {};

      const users = await User.find(filter, {
        username: 1,
        email: 1,
        fullName: 1,
        role: 1,
        maxDevices: 1,
        createdAt: 1,
      })
        .sort({ createdAt: -1 })
        .limit(100);

      res.json({ success: true, users });
    } catch (err) {
      console.error("List users error:", err);
      res.status(500).json({ success: false, error: "Internal server error" });
    }
  }
);

// POST /admin/users/:userId/sessions/revoke-all
admin.post(
  "/users/:userId/sessions/revoke-all",
  authenticateToken,
  requireRole("superadmin"),
  async (req, res) => {
    try {
      const { userId } = req.params;
      if (!isValidId(userId)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid userId" });
      }
      const result = await Session.updateMany(
        { userId, revokedAt: null },
        { $set: { revokedAt: new Date() } }
      );
      res.json({
        success: true,
        revokedCount: result.modifiedCount || 0,
      });
    } catch (err) {
      console.error("Revoke all sessions error:", err);
      res.status(500).json({ success: false, error: "Internal server error" });
    }
  }
);

// Set max devices for a user
admin.post(
  "/users/:userId/max-devices",
  authenticateToken,
  requireRole("superadmin"),
  async (req, res) => {
    try {
      const { userId } = req.params;
      if (!isValidId(userId)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid userId" });
      }

      const maxDevicesNum = Number(req.body.maxDevices);
      if (
        !Number.isInteger(maxDevicesNum) ||
        maxDevicesNum < 1 ||
        maxDevicesNum > 10
      ) {
        return res.status(400).json({
          success: false,
          error: "maxDevices must be an integer between 1 and 10",
        });
      }

      const user = await User.findByIdAndUpdate(
        userId,
        { $set: { maxDevices: maxDevicesNum } },
        { new: true }
      );
      if (!user) {
        return res
          .status(404)
          .json({ success: false, error: "User not found" });
      }

      // If currently exceeding limit, revoke oldest to fit
      const active = await Session.find({
        userId: user._id,
        revokedAt: null,
      }).sort({ createdAt: 1 });
      const over = active.length - user.maxDevices;
      if (over > 0) {
        const toRevoke = active.slice(0, over);
        await Session.updateMany(
          { _id: { $in: toRevoke.map((s) => s._id) } },
          { $set: { revokedAt: new Date() } }
        );
      }

      return res.json({
        success: true,
        userId: user._id,
        maxDevices: user.maxDevices,
      });
    } catch (err) {
      console.error("Set max-devices error:", err);
      return res
        .status(500)
        .json({ success: false, error: "Internal server error" });
    }
  }
);

// List a user's sessions
// Default: active only. Add ?all=true to include revoked.
admin.get(
  "/users/:userId/sessions",
  authenticateToken,
  requireRole("superadmin"),
  async (req, res) => {
    try {
      const { userId } = req.params;
      if (!isValidId(userId)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid userId" });
      }

      const query = { userId };
      if (req.query.all !== "true") {
        query.revokedAt = null;
      }

      const sessions = await Session.find(query).sort({ createdAt: -1 });
      return res.json({ success: true, sessions });
    } catch (err) {
      console.error("List sessions error:", err);
      return res
        .status(500)
        .json({ success: false, error: "Internal server error" });
    }
  }
);

// Revoke a specific session
admin.post(
  "/users/:userId/sessions/:sid/revoke",
  authenticateToken,
  requireRole("superadmin"),
  async (req, res) => {
    try {
      const { userId, sid } = req.params;
      if (!isValidId(userId) || !isValidId(sid)) {
        return res.status(400).json({ success: false, error: "Invalid id(s)" });
      }

      const s = await Session.findOne({ _id: sid, userId });
      if (!s) {
        return res
          .status(404)
          .json({ success: false, error: "Session not found" });
      }
      if (s.revokedAt) {
        return res.json({ success: true, message: "Already revoked" });
      }

      s.revokedAt = new Date();
      await s.save();
      return res.json({ success: true });
    } catch (err) {
      console.error("Revoke session error:", err);
      return res
        .status(500)
        .json({ success: false, error: "Internal server error" });
    }
  }
);

module.exports = admin;
