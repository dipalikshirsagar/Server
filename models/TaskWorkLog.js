const mongoose = require("mongoose");

const taskWorkLogSchema = new mongoose.Schema(
  {
    task: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Task",
      required: true,
    },

    employee: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    date: {
      type: Date,
      required: true,
    },

    startTime: {
      type: String,
      required: true,
    },

    endTime: {
      type: String,
      required: true,
    },

    totalHours: {
      type: Number,
      required: true,
    },

    workDescription: {
      type: String,
      required: true,
    },

    status: {
      type: String,
      enum: ["Submitted", "In Progress", "Pending", "Approved", "Rejected"],
      default: "Pending",
    },

    challengesFaced: String,

    whatLearnedToday: String,

    remarks: {
      type: String,
    },
    rating: {
      type: Number,
      min: 1,
      max: 5,
      default: null,
    },
    progressToday: {
      type: Number,
      min: 0,
      max: 100,
      required: function () {
        return this.status === "In Progress";
      },
    },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },

    approvedAt: Date,
  },
  { timestamps: true }
);

module.exports = mongoose.model("TaskWorkLog", taskWorkLogSchema);
