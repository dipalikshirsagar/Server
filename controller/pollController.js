const mongoose = require("mongoose");
const Poll = require("../models/PollSchema");

exports.createPoll = async (req, res) => {
  try {
    const { question, options, allowMultipleVotes, expiresAt, createdBy } = req.body;

    if (!createdBy) {
      return res.status(400).json({ success: false, message: "createdBy is required" });
    }

    const poll = await Poll.create({
      question,
      options: options.map(opt => ({ text: opt })),
      allowMultipleVotes,
      expiresAt,
      createdBy   
    });

    res.status(201).json({ success: true, data: poll });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};



exports.getAllPolls = async (req, res) => {
  try {
    const polls = await Poll.find()
      .populate("createdBy", "name")
      .sort({ createdAt: -1 });

    res.status(200).json({ success: true, data: polls });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};


exports.getPollById = async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.pollId))
      return res.status(400).json({ message: "Invalid Poll ID" });

    const poll = await Poll.findById(req.params.pollId)
      .populate("options.votes.user", "name");

    if (!poll) return res.status(404).json({ message: "Poll not found" });

    res.status(200).json({ success: true, data: poll });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

/* UPDATE POLL */
exports.updatePoll = async (req, res) => {
  try {
    const poll = await Poll.findByIdAndUpdate(
      req.params.pollId,
      req.body,
      { new: true }
    );
    res.json({ success: true, data: poll });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};


exports.deletePoll = async (req, res) => {
  try {
    await Poll.findByIdAndDelete(req.params.pollId);
    res.json({ success: true, message: "Poll deleted" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};


exports.votePoll = async (req, res) => {
  try {
    const { optionId, userId } = req.body;

    if (!userId) {
      return res.status(400).json({ message: "userId is required" });
    }

    const poll = await Poll.findById(req.params.pollId);
    if (!poll) return res.status(404).json({ message: "Poll not found" });

    const alreadyVoted = poll.options.some(opt =>
      opt.votes.some(v => v.user.toString() === userId)
    );

    if (alreadyVoted && !poll.allowMultipleVotes)
      return res.status(400).json({ message: "You already voted" });

    const option = poll.options.id(optionId);
    if (!option) return res.status(400).json({ message: "Invalid optionId" });

    option.votes.push({ user: userId });

    await poll.save();
    res.json({ success: true, data: poll });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

