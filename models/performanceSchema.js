//Whole  Schema Added by Jayshri
const mongoose = require("mongoose");

const performanceSchema = new mongoose.Schema(
  {
    requestId: { type: String, unique: true },
    managerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: false,
    },
    userId: {
       type: mongoose.Schema.Types.ObjectId,
       ref: "User",
    },
    employeeId: { type: String, required: true },
    employeeName: { type: String, required: true },
    department: { type: String, required: true },
    manager: { type: String, required: true },

    durationType: {
      type: String,
      enum: ["Daily", "Weekly", "Monthly"],
      required: true,
    },

    durationDate: { type: Date, required: true },

    description: { type: String, required: false },

    status: {
      type: String,
      enum: ["Pending", "Added"],
      default: "Pending",
    },

    recommendation: {
      type: String,
      enum: ["Pending", "Promotion", "Increment", "Training"],
      default: "Pending",
    },

    rating: { type: Number, default: null },
    adminStatus: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
      required: true 
    },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    },
    rejectedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User", 
      default: null
    },
    approvedAt: {
      type: Date,
      default: null
    },
    rejectedAt: {
      type: Date,
      default: null
    },
  },
  { timestamps: true }
);


performanceSchema.pre("save", async function (next) {
  if (!this.requestId) {
    const lastRequest = await this.constructor
      .findOne()
      .sort({ createdAt: -1 });

    let nextNumber = 1;

    if (lastRequest?.requestId) {
      const lastNumber = parseInt(lastRequest.requestId.split("-")[1]);
      nextNumber = lastNumber + 1;
    }

    this.requestId = `PERF-${String(nextNumber).padStart(4, "0")}`;
  }
  next();
});

module.exports = mongoose.model("Performance", performanceSchema);