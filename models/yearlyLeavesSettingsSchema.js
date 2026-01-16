const mongoose = require("mongoose");

const yearlyLeavesSettingsSchema = new mongoose.Schema({
  year: {
    type: Number,
    required: true,
    unique: true,
  },
  sl: {
    type: Number,
    required: true,
  },
  cl: {
    type: Number,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const YearlyLeaveSetting = mongoose.model("YearlyLeaveSetting", yearlyLeavesSettingsSchema);
module.exports = YearlyLeaveSetting;
