const mongoose = require("mongoose");

const taskSchema = new mongoose.Schema(
  {
    taskName: { type: String, required: true },
    projectName: { type: String, required: true },
    assignedTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    department: { type: String },
    taskDescription: { type: String, required: true },
    typeOfTask: { type: String, required: true },
    dateOfTaskCreated: { type: Date, default: Date.now },
    dateOfTaskAssignment: { type: Date },
    dateOfExpectedCompletion: { type: Date },
    progressPercentage: { type: String, default: 0, required: true },
    documents: { type: String },
    workingDays: {
    type: Number,
    default: 1,
  },

  dailyEstimatedHours: {
    type: Number,
    default: 0,
  },
    comments: [
      {
        text: {
          type: String,
          required: true,
        },
        user: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    status: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Status",
      required: true,
    },
    priority: {
      type: String,
      enum: ["P1", "P2", "P3", "P4"],
      default: "P3",
      required: true,
    },
    estimatedHours: {type: Number,required: true,min: 0},
    timeTracking: {
      isRunning: { type: Boolean, default: false },
      startTime: { type: Date, default: null },
      totalSeconds: { type: Number, default: 0 },
      timeEntries: [
        {
          startTime: { type: Date, required: true },
          endTime: { type: Date },
          duration: { type: Number, default: 0 },
        },
      ],
    },
  },

  { timestamps: true }
);

taskSchema.post("findOneAndDelete", async function (doc) {
  try {
    if (doc) {
      await TaskLog.deleteMany({ task: doc._id });
    }
  } catch (err) {
    console.error("Error deleting task logs:", err);
  }
});
module.exports = mongoose.model("Task", taskSchema);
