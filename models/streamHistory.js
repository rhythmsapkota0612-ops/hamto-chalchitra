const mongoose = require("mongoose");

const streamHistorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  imdbId: { type: Number },
  tmdbId: { type: Number, required: true },
  isCompleted: { type: Boolean, default: false },
  posterUrl: { type: String },
  backDropUrl: { type: String },
  progressPercentage: { type: Number },
  season: {
    type: String,
    validate: {
      validator: function (val) {
        // Only allow episode if streamType is "tv"
        if (this.streamType === "movie") {
          return val === undefined || val === null;
        }
        return true;
      },
      message: "Season should only be set when streamType is 'tv'",
    },
  },
  streamType: {
    type: String,
    enum: ["movie", "tv"],
    required: true,
  },
  episode: {
    type: String,
    validate: {
      validator: function (val) {
        // Only allow episode if streamType is "tv"
        if (this.streamType === "movie") {
          return val === undefined || val === null;
        }
        return true;
      },
      message: "Episode should only be set when streamType is 'tv'",
    },
  },
  title: String,
  watchedAt: Date,
});

module.exports = mongoose.model("StreamHistory", streamHistorySchema);
