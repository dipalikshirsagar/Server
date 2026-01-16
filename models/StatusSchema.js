const mongoose = require("mongoose");

const StatusSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  description: {
    type: String,
    trim: true,
    default: "",
  },
}, { timestamps: true });

module.exports = mongoose.model("Status", StatusSchema);
