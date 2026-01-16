const express = require("express");
const router = express.Router();

const {
  createTeam,
  getAllTeams,
  getTeamById,
  updateTeam,
  deleteTeam,
  getTeamsByEmployeeId,
  getTeamsCreatedByUserId
} = require("../controller/teamController");

router.get("/createdBy/:userId", getTeamsCreatedByUserId);
router.post("/", createTeam);
router.get("/", getAllTeams);
router.get("/:id", getTeamById);
router.put("/:id", updateTeam);
router.delete("/:id", deleteTeam);
router.get("/employee/:employeeId/teams", getTeamsByEmployeeId);


module.exports = router;
