const mongoose = require("mongoose");

const policySchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 50,
    },

    description: {
      type: String,
      required: true,
      maxlength: 200,
    },

    image: {
      type: String, // image URL or uploaded file path
      required: false,
    },
  },
  { timestamps: true }
);

const Policy = mongoose.model("Policy", policySchema);
module.exports = Policy;
