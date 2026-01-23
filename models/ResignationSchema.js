const mongoose = require("mongoose");

const resignationSchema = new mongoose.Schema({
  resignationId: {
    type: String,
    required: true,
    unique: true,
  },
  employee: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  applyDate: {
    type: Date,
    default: Date.now,
  },
  lastWorkingDay: {
    type: Date,
    required: false,
  },
  reason: {
    type: String,
    required: true,
    enum: [
      "Career Growth",
      "Personal Reason",
      "Higher Studies",
      "Health Issue",
      "Relocation",
      "Other",
    ],
  },
  comments: {
    type: String,
    default: "",
  },
  status: {
    type: String,
    enum: ["Pending", "Approved", "Rejected", "Withdrawn"],
    default: "Pending",
  },
  approverComment: {
    type: String,
    default: "-",
  },
   approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },
  approvedDate: {
    type: Date,
    default: null,
  }
}, { timestamps: true });

module.exports = mongoose.model("Resignation", resignationSchema);