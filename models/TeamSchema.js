const mongoose = require("mongoose");

const TeamSchema = new mongoose.Schema(
  {
    name: {type: String,required: true},
    project: {type: mongoose.Schema.Types.ObjectId,ref: "Project",required: true},
    department: {type: String,required: true},
    assignToProject: {
      type: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
          required: true
        }
      ],
      default: []
    },
     createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Team", TeamSchema);
