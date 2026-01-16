const mongoose = require("mongoose");

const officeLocationSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },      // e.g., "Pune Office"
    lat: { type: Number, required: true },
    lng: { type: Number, required: true },
    address: { type: String },
  },
  { timestamps: true }
);

module.exports = mongoose.model("OfficeLocation", officeLocationSchema);
