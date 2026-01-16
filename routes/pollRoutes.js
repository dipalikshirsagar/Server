const express = require("express");
const router = express.Router();
const pollController = require("../controller/pollController");

router.post("/", pollController.createPoll);
router.get("/", pollController.getAllPolls);
router.get("/:pollId", pollController.getPollById);
router.put("/:pollId", pollController.updatePoll);
router.delete("/:pollId", pollController.deletePoll);
router.post("/:pollId/vote", pollController.votePoll);

module.exports = router;
