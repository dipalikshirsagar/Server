const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    type: { type: String, required: true }, // "Leave", "Regularization", "Event"
    message: { type: String, required: true },
    triggeredByRole: {
      type: String,
      enum: ["EMPLOYEE", "IT_Support"],
      required: true,
    },
    interviewRef: { type: mongoose.Schema.Types.ObjectId, ref: "Interview" },
    //   // snehal added 16-01-2026
    ticketRef: { type: mongoose.Schema.Types.ObjectId, ref: "Ticket" },
    leaveRef: { type: mongoose.Schema.Types.ObjectId, ref: "Leave" },
    regularizationRef: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Attendance",
    },
    announcementRef: { type: mongoose.Schema.Types.ObjectId, ref: "Announcement" },//added by rutuja 
    holidayRef: { type: mongoose.Schema.Types.ObjectId, ref: "Holiday" },//added by rutuja
    eventRef: { type: mongoose.Schema.Types.ObjectId, ref: "Event" },
    isRead: { type: Boolean, default: false },
  },
  { timestamps: true },
);

module.exports = mongoose.model("Notification", notificationSchema);
