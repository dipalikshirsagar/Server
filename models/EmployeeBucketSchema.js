const EmployeeBucketSchema = new mongoose.Schema({
  employeeId: { type: mongoose.Schema.Types.ObjectId, ref: "User", unique: true },
  sickLeave: { type: Number, default: 0 },
  casualLeave: { type: Number, default: 0 },
  lwp: { type: Number, default: 0 }
});

module.exports = mongoose.model("EmployeeBucket", EmployeeBucketSchema);
