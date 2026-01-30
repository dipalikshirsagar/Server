// const mongoose = require("mongoose");

// const ProjectSchema = new mongoose.Schema(
//   {
//     name: {
//       type: String,
//       required: true
//     },

//     projectCode: {
//       type: String,
//       required: true
//     },

//     description: {
//       type: String
//     },

//     managers: [
//       {
//         type: mongoose.Schema.Types.ObjectId,
//         ref: "User",
//         required: true
//       }
//     ],

//     assignedEmployees: {
//       type: [
//         {
//           type: mongoose.Schema.Types.ObjectId,
//           ref: "User",
//           required: false,
//         }
//       ],
//       default: []
//     },

//     clientName: {
//       type: String
//     },

//     startDate: {
//       type: Date,
//       required: true
//     },

//     endDate: {
//       type: Date,
//       required: true
//     },

//     dueDate: {
//       type: Date,
//       required: true
//     }
//     ,
//     status: {
//       type: mongoose.Schema.Types.ObjectId, ref: "Status",
//       required: true
//     },

//     progressPercentage: {
//       type: Number,
//       default: 0
//     },

//     priority: {
//       type: String,
//       enum: ["P1", "P2", "P3", "P4"],
//       required: "true"
//     },

//     budget: {
//       type: Number,
//       default: 0
//     },

//     spendBudget: {
//       type: Number,
//       default: 0
//     },

//     category: {
//       type: String,
//       enum: ["internal", "external"],
//       default: "internal"
//     },

//     attachments: {
//       type: [String],
//       default: []
//     },

//     tags: {
//       type: [String],
//       default: []
//     },
//     comments: [{
//       text: String,
//       user: {
//         type: mongoose.Schema.Types.ObjectId,
//         ref: 'User'
//       },
//       createdAt: {
//         type: Date,
//         default: Date.now
//       }
//     }]

//   },
//   { timestamps: true }
// );

// module.exports = mongoose.model("Project", ProjectSchema);

const mongoose = require("mongoose");

const ProjectSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    projectCode: { type: String, required: true },
    description: String,

    managers: [
      { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    ],
    assignedEmployees: {
      type: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
          required: false,
        },
      ],
      default: [],
    },

    clientName: String,
    startDate: { type: Date, required: true },
    // endDate: { type: Date, required: true },
    dueDate: { type: Date, required: true },

    manualStatus: {
      type: String,
      enum: ["Completed", "Cancelled"],
      default: null,
    },

    manualStatusUpdatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    manualStatusUpdatedAt: {
      type: Date,
      default: null,
    },

    progressPercentage: { type: Number, default: 0 },
    priority: { type: String, enum: ["P1", "P2", "P3", "P4"], required: true },
    budget: {
      type: Number,
      default: 0,
    },

    spendBudget: {
      type: Number,
      default: 0,
    },

    category: {
      type: String,
      enum: ["internal", "external"],
      default: "internal",
    },

    attachments: {
      type: [String],
      default: [],
    },

    tags: {
      type: [String],
      default: [],
    },

    comments: [
      {
        text: String,
        user: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
  },
  { timestamps: true },
);

ProjectSchema.virtual("status").get(function () {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const start = new Date(this.startDate);
  const due = new Date(this.dueDate);
  due.setHours(0, 0, 0, 0);

  if (this.manualStatus) return this.manualStatus;

  if (!due) return "—";

  if (today.getTime() === due.getTime()) {
    return "Today is last date";
  }

  if (start && start > today) {
    return "Upcoming Project";
  }

  if (today > due) {
    return "Delayed";
  }

  //  ON TRACK
  // started + future due date (not upcoming)
  if (start && start <= today && today < due) {
    return "On Track";
  }

  //  NOT STARTED
  if (!start) {
    return "Not Started";
  }
  return "In Progress";
});

ProjectSchema.set("toJSON", { virtuals: true });
ProjectSchema.set("toObject", { virtuals: true });

module.exports = mongoose.model("Project", ProjectSchema);
