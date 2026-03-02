const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    type: { type: String, required: true }, // "Leave", "Regularization", "Event"
    message: { type: String, required: true },
    //Added by Rutuja
    // triggeredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    triggeredByRole: {
      type: String,
      enum: [
        "EMPLOYEE",
        "MANAGER",
        "HR",
        "ADMIN",
        "CEO",
        "COO",
        "MD",
        "IT_Support",
      ],
      // required: true,
    }, //Added by
    interviewRef: { type: mongoose.Schema.Types.ObjectId, ref: "Interview" },
    //   // snehal added 16-01-2026
    ticketRef: { type: mongoose.Schema.Types.ObjectId, ref: "Ticket" },
    leaveRef: { type: mongoose.Schema.Types.ObjectId, ref: "Leave" },
    regularizationRef: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Attendance",
    },
    announcementRef: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Announcement",
    }, //added by rutuja
    pollRef: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: "Poll" 
    },//rutuja
    holidayRef: { type: mongoose.Schema.Types.ObjectId, ref: "Holiday" }, //added by rutuja
    eventRef: { type: mongoose.Schema.Types.ObjectId, ref: "Event" },

    isRead: { type: Boolean, default: false },
  },
  { timestamps: true },
);

module.exports = mongoose.model("Notification", notificationSchema);
