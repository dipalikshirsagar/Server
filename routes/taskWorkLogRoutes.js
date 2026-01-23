const express = require("express");
const router = express.Router();
const {
  createWorkLog,
  getEmployeeLogs,
  getAllLogs,
  updateWorkLog,
  approveRejectLog,
  deleteWorkLog,
  getLogsByManager,
  getTaskLogById,
  getDailyWorkload,
  getWeeklyWorkload,
  getMonthlyWorkload,
} = require("../controller/taskWorkLogController");
const authenticate = require("../authMiddleware/authenticate");

router.post("/", authenticate, createWorkLog); // create
router.get("/employee/:id", getEmployeeLogs); // get logs for employee
router.get("/manager/:managerId/logs", getLogsByManager); // get logs for manager
router.get("/", getAllLogs); // get all logs
router.get("/daily-workload", getDailyWorkload); //get workload by date
router.get("/:id", getTaskLogById); //get logs by id
router.put("/approve/:id", authenticate, approveRejectLog); // approve/reject first
router.put("/:id", authenticate, updateWorkLog); // generic update
router.delete("/:id", deleteWorkLog); // delete

router.get("/workload/weekly", getWeeklyWorkload);
router.get("/workload/monthly", getMonthlyWorkload);

module.exports = router;
