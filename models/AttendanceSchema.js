
const mongoose = require("mongoose");

const attendanceSchema = new mongoose.Schema(
  {
    employee: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    date: { type: Date, required: true },

    checkIn: { type: Date },
    checkOut: { type: Date },
    workingHours: { type: Number, default: 0 },

  
    regularizationRequest: {
      checkIn: { type: Date },
      checkOut: { type: Date },
      status: {
        type: String,
        enum: ["Pending", "Approved", "Rejected"],
        default: null,
      },
      reason: { type: String },
       workMode: String,
      requestedAt: { type: Date },
      reviewedAt: { type: Date },
      // New fields for approver info
      approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      approvedByRole: { type: String, enum: ["manager", "admin"] },
      approvedByName: { type: String }, // optional, store approver's name for display
    },

    dayStatus: {
      type: String,
      enum: ["Absent", "Half Day", "Present", "Leave"],
      default: "Absent",
    },

    leaveType: {
      type: String,
      enum: ["SL", "CL","LWP", null], // Sick, Casual
      default: null,
    },

    leaveRef: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Leave",
      default: null,
    },
//wfo
    checkInLocation: { lat: Number, lng: Number, address: String },
    checkOutLocation: { lat: Number, lng: Number, address: String },

    employeeCheckInLocation: { lat: Number, lng: Number, address: String },
    employeeCheckOutLocation: { lat: Number, lng: Number, address: String },

    // Mode: Office / WFH
    mode: {
      type: String,
      enum: ["Office", "WFH"],
      default: "Office",
    },

    // WFH approval request (optional, to track admin approval)
    wfhRequest: {
      status: {
        type: String,
        enum: ["Pending", "Approved", "Rejected", null],
        default: null,
      },
      requestedAt: { type: Date },
      reviewedAt: { type: Date },
  },
},
  { timestamps: true }
);

attendanceSchema.index({ employee: 1, date: 1 }, { unique: true });

module.exports = mongoose.model("Attendance", attendanceSchema);
