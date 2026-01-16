// const mongoose = require("mongoose");

// const gallerySchema = new mongoose.Schema(
//   {
//     title: String,
//     description: String,
//     type: {
//       type: String,
//       enum: ["image", "video", "pdf"],
//     },
//     url: String,
//     public_id: String,
//   },
//   { timestamps: true }
// );

// module.exports = mongoose.model("Gallery", gallerySchema);

//Added category field to the schema  of snehal
const mongoose = require("mongoose");

const gallerySchema = new mongoose.Schema(
  {
    title: String,
    description: String,
    category: {
      type: String,
      enum: [
        "Rewards & Recognition",
        "Engagement Activities",
        "Social Activities",
      ],
      required:true,
    },
    type: {
      type: String,
      enum: ["image", "video", "pdf"],
      required:true,
    },
    url: String,
    public_id: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model("Gallery", gallerySchema);