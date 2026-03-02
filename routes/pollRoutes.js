const express = require("express");
const router = express.Router();

const {
  createPoll,
  getActivePoll,
  getPreviousPolls,
  votePoll,
  getPollVotedMembers, 
  deletePoll, 
  editPoll  
} = require("../controller/pollController");


router.post("/create", createPoll);  
router.get("/active", getActivePoll);
router.get("/previous", getPreviousPolls);
router.post("/vote", votePoll);
router.get("/:pollId/voted-members", getPollVotedMembers);
router.delete("/:pollId", deletePoll);
router.put("/:pollId", editPoll);//rutuja

module.exports = router;