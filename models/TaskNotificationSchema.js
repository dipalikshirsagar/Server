const mongoose = require("mongoose");

const TaskNotificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  type: { type: String, required: true }, 
  message: { type: String, required: true },
  taskRef: { type: mongoose.Schema.Types.ObjectId, ref: "Task" },
  projectRef: { type: mongoose.Schema.Types.ObjectId, ref: "Project" },
  isRead:{type:Boolean, default:false}
}, { timestamps: true });

module.exports = mongoose.model("TaskNotification", TaskNotificationSchema);