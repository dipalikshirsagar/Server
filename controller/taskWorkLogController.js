const TaskWorkLog = require("../models/TaskWorkLog");
const Task = require("../models/TaskSchema");
const Employee = require("../models/User");
const workloadService = require("../services/workloadService");
const { getEmployeeWorkloadByRange } = require("../services/workloadService");
const { getEmployeeWorkloadByWeekRange } = require("../services/workloadService");
const mongoose = require("mongoose");

// Create Work Log
exports.createWorkLog = async (req, res) => {
  try {
    const allowedRoles = ["employee"];

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden: Access denied" });
    }
    const {
      task,
      employee,
      startTime,
      endTime,
      workDescription,
      challengesFaced,
      whatLearnedToday,
      progressToday,
    } = req.body;

    if (
      !task ||
      !employee ||
      !startTime ||
      !endTime ||
      !workDescription ||
      !challengesFaced ||
      !whatLearnedToday
    ) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const taskExists = await Task.findById(task);
    if (!taskExists)
      return res.status(404).json({ message: "Task not found." });

    const employeeExists = await Employee.findById(employee);
    if (!employeeExists)
      return res.status(404).json({ message: "Employee not found." });
    const status = req.body.status;
    console.log("status", req.body.status);
    // 🔒 Validate progressToday only when Pending
    if (status === "In Progress") {
      if (progressToday === undefined || progressToday === null) {
        return res.status(400).json({
          message: "progressToday is required when status is Pending.",
        });
      }

      if (progressToday < 0 || progressToday > 100) {
        return res.status(400).json({
          message: "progressToday must be between 0 and 100.",
        });
      }
    }
    console.log("progressToday", progressToday);

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const alreadyLogged = await TaskWorkLog.findOne({
      task,
      employee,
      date: today,
    });
    if (alreadyLogged)
      return res
        .status(400)
        .json({ message: "Work log already submitted for today." });

    // ⏱ Convert time to minutes for comparison
    const convertToMinutes = (time) => {
      const [h, m] = time.split(":").map(Number);
      return h * 60 + m;
    };

    if (convertToMinutes(startTime) >= convertToMinutes(endTime)) {
      return res
        .status(400)
        .json({ message: "Start time must be earlier than end time." });
    }

    const totalHours =
      (convertToMinutes(endTime) - convertToMinutes(startTime)) / 60;

    const log = await TaskWorkLog.create({
      task,
      employee,
      date: today,
      startTime,
      endTime,
      totalHours,
      workDescription,
      challengesFaced,
      whatLearnedToday,
      status,
      ...(status === "In Progress" && { progressToday }),
    });
    console.log("log", log);
    res.status(201).json({ message: "Task log submitted successfully.", log });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Failed to create log", error: err.message });
  }
};

// Get logs by employee
exports.getEmployeeLogs = async (req, res) => {
  try {
    const logs = await TaskWorkLog.find({ employee: req.params.id })
      .populate({
        path: "task",
      })
      .populate({
        path: "approvedBy",
        select: "name email",
      })
      .populate({
        path: "employee",
        select: "name",
      })
      .sort({ date: -1 });

    // Filter out logs where populate returned null
    const filteredLogs = logs.filter((log) => log.task !== null);

    res.json(filteredLogs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch logs" });
  }
};

// Get all logs (Admin / HR / Manager)
exports.getAllLogs = async (req, res) => {
  try {
    const logs = await TaskWorkLog.find()
      .populate({
        path: "task",
      })
      .populate({
        path: "employee",
      })
      .populate({
        path: "approvedBy",
        select: "name email",
      })
      .sort({ date: -1 });
    // Filter out logs where populate returned null
    const filteredLogs = logs.filter((log) => log.task !== null);

    res.json(filteredLogs);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch logs" });
  }
};

// Update Work Log (Employee before approval)
exports.updateWorkLog = async (req, res) => {
  try {
    const allowedRoles = ["employee"];

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden: Access denied" });
    }
    const { id } = req.params;

    const {
      task,
      employee,
      startTime,
      endTime,
      workDescription,
      challengesFaced,
      whatLearnedToday,
      progressToday,
    } = req.body;

    if (
      !task ||
      !employee ||
      !startTime ||
      !endTime ||
      !workDescription ||
      !challengesFaced ||
      !whatLearnedToday
    ) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const log = await TaskWorkLog.findById(id);
    if (!log) return res.status(404).json({ message: "Work log not found." });

    if (log.status === "Approved") {
      return res
        .status(403)
        .json({ message: "Approved logs cannot be edited." });
    }

    const taskExists = await Task.findById(task);
    if (!taskExists)
      return res.status(404).json({ message: "Task not found." });

    const employeeExists = await Employee.findById(employee);
    if (!employeeExists)
      return res.status(404).json({ message: "Employee not found." });

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    if (
      new Date(log.date).getTime() !== today.getTime() &&
      log.status !== "Pending"
    ) {
      return res
        .status(403)
        .json({ message: "Only today's or pending work logs can be updated." });
    }

    const convertToMinutes = (time) => {
      const [h, m] = time.split(":").map(Number);
      return h * 60 + m;
    };

    if (convertToMinutes(startTime) >= convertToMinutes(endTime)) {
      return res
        .status(400)
        .json({ message: "Start time must be less than end time." });
    }

    const totalHours =
      (convertToMinutes(endTime) - convertToMinutes(startTime)) / 60;

    const status = req.body.status || log.status;

    // 🔒 progressToday rules
    if (status === "In Progress") {
      if (progressToday === undefined || progressToday === null) {
        return res.status(400).json({
          message: "progressToday is required when status is In progress.",
        });
      }

      if (progressToday < 0 || progressToday > 100) {
        return res.status(400).json({
          message: "progressToday must be between 0 and 100.",
        });
      }

      log.progressToday = progressToday;
    } else if (progressToday !== undefined) {
      return res.status(403).json({
        message: "progressToday can only be updated when status is Pending.",
      });
    }
    console.log("progressToday", progressToday);

    log.task = task;
    log.employee = employee;
    log.startTime = startTime;
    log.endTime = endTime;
    log.totalHours = totalHours;
    log.workDescription = workDescription;
    log.challengesFaced = challengesFaced;
    log.whatLearnedToday = whatLearnedToday;
    log.status = req.body.status;

    await log.save();
    console.log("log", log);

    res.status(200).json({ message: "Work log updated successfully.", log });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Failed to update work log.", error: err.message });
  }
};

//get tasklog by idd
exports.getTaskLogById = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid TaskLog ID" });
    }

    const log = await TaskWorkLog.findById(id)
      .populate("task")
      .populate("employee", "-password -refreshToken")
      .populate("approvedBy", "name email");

    if (!log) {
      return res.status(404).json({ message: "Task log not found" });
    }

    res.status(200).json(log);
  } catch (err) {
    console.error("Get TaskLog by ID error:", err);
    res
      .status(500)
      .json({ message: "Failed to fetch task log", error: err.message });
  }
};

// Approve / Reject Log
exports.approveRejectLog = async (req, res) => {
  try {
    const allowedRoles = ["manager"];
    console.log(req.user);
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden: Access denied" });
    }
    const { status, remarks, rating } = req.body;

    const log = await TaskWorkLog.findByIdAndUpdate(
      req.params.id,
      {
        status,
        remarks,
        rating,
        approvedBy: req.user.id,
        approvedAt: new Date(),
      },
      { new: true },
    );

    res.json(log);
  } catch (err) {
    res.status(500).json({ message: "Approval failed" });
  }
};

// Delete Log (Employee only when pending)
exports.deleteWorkLog = async (req, res) => {
  try {
    const log = await TaskWorkLog.findById(req.params.id);
    if (!log || log.status !== "Pending")
      return res.status(400).json({ message: "Cannot delete approved log" });

    await log.deleteOne();
    res.json({ message: "Log deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Delete failed" });
  }
};

//get logs by manager
exports.getLogsByManager = async (req, res) => {
  try {
    const managerId = req.params.managerId.toString();
    console.log(typeof managerId);

    const logs = await TaskWorkLog.aggregate([
      {
        $lookup: {
          from: "tasks",
          localField: "task",
          foreignField: "_id",
          as: "task",
        },
      },
      { $unwind: "$task" },

      {
        $match: {
          "task.createdBy": managerId, // string-to-string match
        },
      },

      {
        $lookup: {
          from: "employees",
          localField: "employee",
          foreignField: "_id",
          as: "employee",
        },
      },
      { $unwind: "$employee" },

      { $sort: { date: -1 } },
    ]);

    res.status(200).json(logs);
  } catch (err) {
    res
      .status(500)
      .json({ message: "Failed to fetch manager logs", error: err.message });
  }
};

//get workload
exports.getDailyWorkload = async (req, res) => {
  try {
    const { date } = req.query;

    if (!date) {
      return res.status(400).json({ message: "Date is required" });
    }

    const data = await workloadService.getDailyEmployeeWorkload(date);

    res.status(200).json({
      date,
      data,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};

// get weekly workload

function getWeekRange(date) {
  const d = new Date(date);
  const day = d.getDay(); // 0 (Sun) - 6 (Sat)
  const diffToMonday = d.getDate() - day + (day === 0 ? -6 : 1);

  const start = new Date(d.setDate(diffToMonday));
  start.setHours(0, 0, 0, 0);

  const end = new Date(start);
  end.setDate(start.getDate() + 6);
  end.setHours(23, 59, 59, 999);

  return { start, end };
}

exports.getWeeklyWorkload = async (req, res) => {
  const { date } = req.query;

  const { start, end } = getWeekRange(date);

  // const data = await getEmployeeWorkloadByWeekRange(start, end, 9 * 5); // 5 working days
  const data = await getEmployeeWorkloadByWeekRange(start, end);

  res.json({
    week: `${start.toISOString()} - ${end.toISOString()}`,
    data,
  });
};

//get monthly workload

function getMonthRange(year, month) {
  const start = new Date(year, month - 1, 1);
  start.setHours(0, 0, 0, 0);

  const end = new Date(year, month, 0);
  end.setHours(23, 59, 59, 999);

  return { start, end };
}

exports.getMonthlyWorkload = async (req, res) => {
  const { year, month } = req.query;

  const { start, end } = getMonthRange(year, month);

  //  const workingDays = 22; // average
  const data = await getEmployeeWorkloadByRange(start, end);

  res.json({
    month,
    year,
    data,
  });
};
