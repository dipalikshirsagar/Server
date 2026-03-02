const mongoose = require("mongoose");
const optionSchema = new mongoose.Schema(
  {
  text: { type: String, required: true, trim: true },
  votes: { type: Number, default: 0 },
});
const pollSchema = new mongoose.Schema(
  {
    question: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    options: {
      type: [optionSchema],
      validate: [
        arr => arr.length >= 2,
        "Poll must have at least 2 options"
      ]
    },
    votedUsers: [
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    optionIndex: { type: Number }
  }
],
    isActive: { type: Boolean, default: true, index: true }
  },
  { timestamps: true }
);

const pollVoteSchema = new mongoose.Schema(
  {
  pollId: { type: mongoose.Schema.Types.ObjectId, ref: "Poll", required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  optionIndex: { type: Number, required: true },
  votedAt: { type: Date, default: Date.now }
}, { timestamps: true });


module.exports = mongoose.model("Poll", pollSchema);