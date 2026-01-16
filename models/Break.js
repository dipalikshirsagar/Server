const mongoose = require("mongoose");

const SingleBreakSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["Tea", "Lunch", "Personal",  "Other"],
      required: true,
    },
    reason: {
      type: String,
      default: "",
    },
    startTime: {
      type: Date,
      required: true,
    },
    endTime: {
      type: Date,
    },
    durationSeconds: {
      type: Number,
      default: 0,
    },
  },
  { _id: false }
);

const BreakSchema = new mongoose.Schema(
  {
    employeeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    date: {
      type: Date,
      required: true,
      index: true,
    },

    breaks: [SingleBreakSchema],

    totalBreakSeconds: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);

// One document per employee per day
BreakSchema.index({ employeeId: 1, date: 1 }, { unique: true });

module.exports = mongoose.model("Break", BreakSchema);