const express = require("express");
const router = express.Router();
const jobController = require("../controller/jobController");



router.post("/",
 jobController.createJob);
router.get("/", jobController.getAllJobs);
router.put("/:id", jobController.updateJob);
router.delete("/:id", jobController.deleteJob);
router.get("/:id", jobController.getJobById);



module.exports = router;
