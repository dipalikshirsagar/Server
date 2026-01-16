
const mongoose = require("mongoose");

const ProjectSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true
    },

    projectCode: {
      type: String,
      required: true
    },

    description: {
      type: String
    },

    managers: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      }
    ],

    assignedEmployees: {
      type: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
          required: false,
        }
      ],
      default: []
    },

    clientName: {
      type: String
    },

    startDate: {
      type: Date,
      required: true
    },

    endDate: {
      type: Date,
      required: true
    },

    dueDate: {
      type: Date,
      required: true
    }
    ,
    status: {
      type: mongoose.Schema.Types.ObjectId, ref: "Status",
      required: true
    },

    progressPercentage: {
      type: Number,
      default: 0
    },

    priority: {
      type: String,
      enum: ["P1", "P2", "P3", "P4"],
      required: "true"
    },

    budget: {
      type: Number,
      default: 0
    },

    spendBudget: {
      type: Number,
      default: 0
    },

    category: {
      type: String,
      enum: ["internal", "external"],
      default: "internal"
    },

    attachments: {
      type: [String],
      default: []
    },

    tags: {
      type: [String],
      default: []
    },
    comments: [{
      text: String,
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      createdAt: {
        type: Date,
        default: Date.now
      }
    }]



  },
  { timestamps: true }
);

module.exports = mongoose.model("Project", ProjectSchema);

