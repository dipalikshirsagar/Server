const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  type: { type: String, required: true }, // "Leave", "Regularization", "Event"
  message: { type: String, required: true },
  leaveRef: { type: mongoose.Schema.Types.ObjectId, ref: "Leave" },
  regularizationRef: { type: mongoose.Schema.Types.ObjectId, ref: "Attendance" },
  eventRef: { type: mongoose.Schema.Types.ObjectId, ref: "Event" },
  isRead:{type:Boolean, default:false}
}, { timestamps: true });

module.exports = mongoose.model("Notification", notificationSchema);
