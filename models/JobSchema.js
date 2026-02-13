const mongoose = require("mongoose");

const JobSchema = new mongoose.Schema({
  jobTitle: { type: String, required: true },
  department: { type: String, required: true },
  grade: String,
  location: String,

  jobType: { type: String, enum: ["inhouse", "referral"], required: true },
  hiringType: String,

  noOfOpenings: { type: Number, min: 1, required: true },

  jobDescription: String,

  ctc: {
    min: Number,
    max: Number
  },

  experience: {
    min: Number,
    max: Number
  },

  importantSkills: [String],
  dueOn: Date,
  status: { type: String, enum: ["OnHold", "Active", "Closed"], default: "Active" },
  createdBy:{ type: mongoose.Schema.Types.ObjectId, ref: "User" },
  
}, { timestamps: true });

module.exports = mongoose.model("Job", JobSchema);

