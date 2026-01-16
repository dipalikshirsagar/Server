const mongoose = require("mongoose");

const pollSchema = new mongoose.Schema(
  {
    question: String,
    options: [
      {
        text: String,
        votes: [
          {
            user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
            votedAt: { type: Date, default: Date.now }
          }
        ]
      }
    ],
    allowMultipleVotes: Boolean,
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    expiresAt: Date,
    isActive: { type: Boolean, default: true }
  },
  { timestamps: true }
);

pollSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("Poll", pollSchema);
