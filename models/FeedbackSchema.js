const mongoose = require("mongoose");

const FeedbackSchema = new mongoose.Schema({
  feedbackId: {
    type: String,
    unique: true
  },
  sender: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: "User", 
    required: true 
  },
  receiver: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: "User", 
    required: true 
  },
  title: {
    type: String,
    required: true
  },
  message: { 
    type: String, 
    required: true 
  },
  status: {
    type: String,
    enum: ["pending", "viewed"],
    default: "pending"
  },
  readAt: { 
    type: Date, 
    default: null 
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("Feedback", FeedbackSchema);