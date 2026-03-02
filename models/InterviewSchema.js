const mongoose = require("mongoose");

const interviewSchema = new mongoose.Schema(
  {
    interviewId: {
      type: String,
      unique: true,
    },

    // ===== Candidate Info =====
    candidateName: {
      type: String,
      required: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },

    role: {
      type: String,
      required: true,
      enum: [
        "Tester",
        "Software Developer",
        "Java Developer",
        "Frontend Developer",
        "Backend Developer",
        "Full Stack Developer",
      ],
    },

    // ===== Interview Details =====
    date: {
      type: String,
      required: true,
    },

    startTime: {
      type: String,
      required: true,
    },

    duration: {
      type: String,
      trim: true,
    },

    endTime: {
      type: String,
      required: true,
    },

    comment: {
      type: String,
      trim: true,
      maxlength: 500,
      default: "",
    },

    interviewType: {
      type: String,
      enum: ["Online", "Offline"],
      default: "Online",
    },

    interviewer: {
      type: String, // optional if using interviewerName
      required: false,
    },

    interviewerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User", // ya Employee model ka naam
      required: true,
    },

    interviewerName: {
      type: String,
    },

    resumeUrl: {
      type: String,
    },

    link: {
      type: String,
      required: function () {
        return this.interviewType === "Online";
      },
      trim: true,
    },

    // status: {
    //   type: String,
    //   enum: [
    //     "Scheduled",
    //     "On-going",
    //     "Completed",
    //     "Cancelled",
    //     "Not-completed",
    //   ],
    //   default: "Scheduled",
    // },
    manualStatus: {
      type: String,
      enum: ["Cancelled", "Not-completed","Scheduled"],
      default: "Scheduled",
    },

  },
  {
    timestamps: true,
  },
);

// 🔥 AUTO GENERATE INTERVIEW ID
interviewSchema.pre("save", async function (next) {
  if (!this.interviewId) {
    const randomNumber = Math.floor(100000 + Math.random() * 900000);
    this.interviewId = `INT-${randomNumber}`;
  }
  next();
});

interviewSchema.virtual("status").get(function () {
  const now = new Date();

  // 🔥 Manual override first
  if (this.manualStatus) return this.manualStatus;

  if (!this.date || !this.startTime || !this.endTime) return "Scheduled";

  // Create datetime objects
  const startDateTime = new Date(`${this.date}T${this.startTime}`);
  const endDateTime = new Date(`${this.date}T${this.endTime}`);

  // If now between start and end → ONGOING
  if (now >= startDateTime && now <= endDateTime) {
    return "On-going";
  }

  // If now > end → COMPLETED
  if (now > endDateTime) {
    return "Completed";
  }

  // If future → SCHEDULED
  if (now < startDateTime) {
    return "Scheduled";
  }

  return "Scheduled";
});

interviewSchema.set("toJSON", { virtuals: true });
interviewSchema.set("toObject", { virtuals: true });


module.exports = mongoose.model("Interview", interviewSchema);