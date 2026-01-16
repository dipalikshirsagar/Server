const mongoose = require("mongoose");

const weeklyOffSchema = new mongoose.Schema({
  year: { type: Number, required: true, unique: true }, // one config per year
  saturdays: [{ type: Number, required: true }], // e.g., [1,3,5]
  holidays: [
    {
      name: { type: String, required: true },
      date: { type: Date, required: true },
      description: { type: String },
    },
]
});

module.exports = mongoose.model("WeeklyOff", weeklyOffSchema);
