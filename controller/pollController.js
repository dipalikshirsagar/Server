const Poll = require("../models/PollSchema.js");
const User = require("../models/User");
const Notification = require("../models/notificationSchema"); 


exports.createPoll = async (req, res) => {
  if (!req.body.question || !req.body.options || req.body.options.length < 2) {
  return res.status(400).json({
    message: "Question and at least 2 options are required"
  });
}
  try {
    
    await Poll.updateMany(
      { isActive: true },
      { $set: { isActive: false } }
    );
    // 2️⃣ Create new active poll
    const poll = new Poll({
  question: req.body.question,
  description: req.body.description,  
  options: req.body.options,
  isActive: true
});
    await poll.save();

    // rutuja notification start
    const users = await User.find({ role: { $ne: "admin" } }, "_id");

    const notifications = users.map((user) => ({
      user: user._id,
      type: "Poll",
      message: `New poll: ${poll.question}`,
      triggeredByRole: req.user?.role, 
      pollRef: poll._id, 
      isRead: false,
      createdAt: new Date(),
    }));

    if (notifications.length > 0) {
      await Notification.insertMany(notifications);
    }

    res.status(201).json(poll);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// GET ACTIVE POLL
exports.getActivePoll = async (req, res) => {
  try {
    const poll = await Poll.findOne({ isActive: true });

    console.log("Active Poll From DB →", poll); // ✅ ADD THIS

    res.json(poll);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// GET PREVIOUS POLLS
exports.getPreviousPolls = async (req, res) => {
  try {
    const polls = await Poll.find({ isActive: false })
      .sort({ createdAt: -1 });

    res.json(polls);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// VOTE
exports.votePoll = async (req, res) => {
  try {
    const { pollId, optionIndex, userId } = req.body;

    if (!pollId || optionIndex === undefined || !userId) {
      return res.status(400).json({ message: "Missing fields" });
    }

    // const poll = await Poll.findById(pollId);
    // if (!poll || !poll.isActive) {
    //   return res.status(400).json({ message: "Poll not active" });
    // } 

    const poll = await Poll.findById(pollId);
    if (!poll) {
      return res.status(400).json({ message: "Poll not found" });
    }

const alreadyVoted = poll.votedUsers.some(
  v => v.userId.toString() === userId.toString()
);

if (alreadyVoted) {
  return res.status(400).json({ message: "Already voted" });
}

if (optionIndex < 0 || optionIndex >= poll.options.length) {
  return res.status(400).json({ message: "Invalid option" });
}

poll.options[optionIndex].votes += 1;

poll.votedUsers.push({
  userId,
  optionIndex
  });
    const savedPoll = await poll.save();
    res.status(200).json(savedPoll);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};


// rutuja code start
exports.getPollVotedMembers = async (req, res) => {
  try {
    const pollId = req.params.pollId;
    
    const poll = await Poll.findById(pollId)
      .populate({
        path: 'votedUsers.userId',
        select: 'name email role' 
      });
    
    if (!poll) {
      return res.status(404).json({ message: "Poll not found" });
    }

    const votedMembers = poll.votedUsers.map(vote => ({
      userId: vote.userId,
      userName: vote.userId?.name ,
      userEmail: vote.userId?.email,
      userRole: vote.userId?.role,
      optionIndex: vote.optionIndex,
      optionText: poll.options[vote.optionIndex]?.text || `Option ${vote.optionIndex + 1}`,
      votedAt: vote.votedAt || vote.createdAt
    }));

    res.json(votedMembers);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.deletePoll = async (req, res) => {
  try {
    const pollId = req.params.pollId;
    
    const poll = await Poll.findById(pollId);
    
    if (!poll) {
      return res.status(404).json({ message: "Poll not found" });
    }

     // Delete notification of this poll if delete
     await Notification.deleteMany({ pollRef: pollId });

    await Poll.findByIdAndDelete(pollId);
    
    res.status(200).json({ 
      message: "Poll deleted successfully",
      deletedPollId: pollId 
    });
    
  } catch (err) {
    console.error("Error deleting poll:", err);
    res.status(500).json({ message: err.message });
  }
};

exports.editPoll = async (req, res) => {
  try {
    const pollId = req.params.pollId;
    const { question, description, options } = req.body;

    if (!question || !options || options.length < 2) {
      return res.status(400).json({
        message: "Question and at least 2 options are required"
      });
    }
    const poll = await Poll.findById(pollId);
    
    if (!poll) {
      return res.status(404).json({ message: "Poll not found" });
    }

    if (!poll.isActive) {
      return res.status(400).json({ 
        message: "Only active polls can be edited" 
      });
    }

    if (poll.votedUsers && poll.votedUsers.length > 0) {
      return res.status(400).json({ 
        message: "Cannot edit poll after votes have been cast" 
      });
    }

    poll.question = question;
    poll.description = description || poll.description;
    
    poll.options = options.map((opt, index) => ({
      text: typeof opt === 'string' ? opt : opt.text,
      votes: poll.options[index]?.votes || 0
    }));

    const updatedPoll = await poll.save();

    await Notification.updateMany(
      { pollRef: pollId, type: "Poll" },
      { 
        $set: { 
          message: `Updated poll: ${updatedPoll.question}`,
          updatedAt: new Date()
        } 
      }
    );

    res.status(200).json({
      message: "Poll updated successfully",
      poll: updatedPoll
    });

  } catch (err) {
    console.error("Error editing poll:", err);
    res.status(500).json({ message: err.message });
  }
};




