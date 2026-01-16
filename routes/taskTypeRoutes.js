// const express = require("express");
// const router = express.Router();
// const {
//   createTaskType,
//   getTaskTypes,
//   getTaskTypeById,
//   updateTaskType,
//   deleteTaskType,
//   getUniqueTaskTypeNames
// } = require("../controller/tasktypeController");

// router.get("/tasktypes/unique-names", getUniqueTaskTypeNames);
// router.post("/", createTaskType);
// router.get("/", getTaskTypes);
// router.get("/:id", getTaskTypeById);
// router.put("/:id", updateTaskType);
// router.delete("/:id", deleteTaskType);


// module.exports = router;

const express = require("express");
const router = express.Router();
const {
  createTaskType,
  getTaskTypes,
  getTaskTypeById,
  updateTaskType,
  deleteTaskType,
  getUniqueTaskTypeNames
} = require("../controller/tasktypeController");

// IMPORTANT: Keep static routes BEFORE dynamic ones

router.get("/unique-names", getUniqueTaskTypeNames);   // <-- FIXED
router.get("/test", (req, res) => res.send("TaskType route working"));

router.post("/", createTaskType);
router.get("/", getTaskTypes);
router.get("/:id", getTaskTypeById);
router.put("/:id", updateTaskType);
router.delete("/:id", deleteTaskType);

module.exports = router;

