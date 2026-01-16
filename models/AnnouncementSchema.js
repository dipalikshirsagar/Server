
const mongoose = require("mongoose");

const AnnouncementSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, required: true },
    publishDate: { type: Date, required: true },
    expirationDate: { type: Date },
    category: { type: String, required: true },
    image: { type: String },
    isActive: { type: Boolean, default: true}
  },
  { timestamps: true }
);

module.exports = mongoose.model("Announcement", AnnouncementSchema);
