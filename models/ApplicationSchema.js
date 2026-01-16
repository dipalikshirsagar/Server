const mongoose = require("mongoose");


const ApplicationSchema = new mongoose.Schema({
  job: { type: mongoose.Schema.Types.ObjectId, ref: "Job", required: true },

  applicantType: { type: String, enum: ["inhouse", "referral"], required: true },

  employee: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // inhouse

  candidate: {
    name: String,
    email: String,
    phone: String,
    experience:Number,
    city:String,
    resumeUrl: String
  },
  resumePublicId:String,
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // referral

  status: {
    type: String,
    enum: ["Applied", "Shortlisted", "Interview", "Hired", "Rejected"],
    default: "Applied"
  }

},
  { timestamps: true });
module.exports = mongoose.model("Application", ApplicationSchema);