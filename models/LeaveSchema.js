const mongoose = require("mongoose");

const leaveSchema = new mongoose.Schema({
  employee: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  leaveType: { type: String, enum: ["SL", "CL", "LWP"], required: true }, // Sick / Casual
  dateTo: { type: Date, required: true },
  dateFrom: { type: Date, required: true },
  duration: { type: String, enum: ["full", "half"], default: "full" },
  reportingManager: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    // required: true,
  },
  reason: { type: String, required: true },
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
  appliedAt: { type: Date, default: Date.now },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  approvedByRole: { type: String, enum: ["manager", "admin"] },
  //approvedByName: { type: String }, // save approver name
  isSandwich: { type: Boolean, default: false }, // 👈 new field
  
});

module.exports = mongoose.model("Leave", leaveSchema);
