const mongoose = require("mongoose");

const TaskTypeSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true
    },

    description: {
      type: String,
          },

    priority: {
      type: String,
      enum: ["P1", "P2", "P3", "P4"],
      required: [true, "Priority is required"]
    },

    isActive: {
      type: Boolean,
      default: true
    },

    assignedDepartment: {
      type: String,
      required:true
    },

    colorCode: {
      type: String,
      //match: /^#([0-9A-F]{3}|[0-9A-F]{6})$/, // Hex color validation
      required: false
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("TaskType", TaskTypeSchema);
