const Job = require("../models/JobSchema");
const User = require("../models/User");              
const Notification = require("../models/notificationSchema");

// CREATE JOB Added  by samiksha
exports.createJob = async (req, res) => {
  try {
    const { ctc, experience, noOfOpenings, dueOn } = req.body;

    // ✅ Number conversion (INSIDE function)
    const ctcMin = Number(ctc?.min);
    const ctcMax = Number(ctc?.max);

    const expMin = Number(experience?.min);
    const expMax = Number(experience?.max);

    const openings = Number(noOfOpenings);

    // ✅ Validations
    if (ctcMin >= ctcMax)
      return res.status(400).json({ error: "CTC min must be less than max" });

    if (expMin >= expMax)
      return res
        .status(400)
        .json({ error: "Experience min must be less than max" });

    if (openings <= 0)
      return res
        .status(400)
        .json({ error: "No of openings must be greater than 0" });

    // ✅ Safe due date validation
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const dueDate = new Date(dueOn);
    dueDate.setHours(0, 0, 0, 0);

    if (dueDate < today)
      return res
        .status(400)
        .json({ error: "Due date must be today or future" });

    const job = await Job.create(req.body);

    // added by shivani
    const notifyUsers = await User.find(
      { role: { $in: ["employee", "manager", "it"] } },
      "_id role"
    );
    
    const jobTypeFormatted =
      job.jobType === "inhouse"
        ? "Inhouse"
        : job.jobType === "referral"
        ? "Referral"
        : "Job";
    
    const notifications = notifyUsers.map((user) => ({
      user: user._id,
      type: "Job",
      message: `New ${jobTypeFormatted} job posted: ${job.jobTitle}`,
      triggeredByRole: "HR", 
      jobRef: job._id,
      isRead: false,
      createdAt: new Date(),
    }));
    
    await Notification.insertMany(notifications);
    // 

    res.status(201).json(job);
  } catch (err) {
    console.error("Create Job Error:", err);
    res.status(400).json({ error: err.message });
  }
};

// UPDATE JOB  added by Samiksha
exports.updateJob = async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job) return res.status(404).json({ error: "Job not found" });

    const { ctc, experience, noOfOpenings, dueOn } = req.body;

    if (ctc) {
      const ctcMin = Number(ctc.min);
      const ctcMax = Number(ctc.max);
      if (ctcMin >= ctcMax)
        return res.status(400).json({ error: "CTC min must be less than max" });
    }

    if (experience) {
      const expMin = Number(experience.min);
      const expMax = Number(experience.max);
      if (expMin >= expMax)
        return res
          .status(400)
          .json({ error: "Experience min must be less than max" });
    }

    if (noOfOpenings !== undefined && Number(noOfOpenings) <= 0)
      return res
        .status(400)
        .json({ error: "No of openings must be greater than 0" });

    // if (dueOn) {
    //   const today = new Date();
    //   today.setHours(0, 0, 0, 0);

    //   const dueDate = new Date(dueOn);
    //   dueDate.setHours(0, 0, 0, 0);

    //   if (dueDate < today)
    //     return res.status(400).json({ error: "Due date must be today or future" });
    // }
    //samiksha
    // ✅ Due date validation
    if (dueOn) {
      const dueDate = new Date(dueOn);

      if (isNaN(dueDate.getTime())) {
        return res.status(400).json({ error: "Invalid due date" });
      }

      const today = new Date();
      today.setHours(0, 0, 0, 0);
      dueDate.setHours(0, 0, 0, 0);

      if (dueDate < today) {
        return res
          .status(400)
          .json({ error: "Due date must be today or future" });
      }
    }

    Object.assign(job, req.body);
    await job.save();

    res.json(job);
  } catch (err) {
    console.error("Update Job Error:", err);
    res.status(400).json({ error: err.message });
  }
};

// // GET JOBS
// exports.getJobs = async (req, res) => {
//   const jobs = await Job.find({ status: "open" });
//   res.json(jobs);
// };

// // DELETE JOB (SOFT DELETE)
// exports.deleteJob = async (req, res) => {
//   await Job.findByIdAndUpdate(req.params.id, { status: "closed" });
//   res.json({ message: "Job closed successfully" });
// };

//get all jobs
//mahesh code
exports.getAllJobs = async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // 🔥 Auto close expired jobs
    await Job.updateMany(
      { dueOn: { $lt: today }, status: { $ne: "Closed" } },
      { $set: { status: "Closed" } },
    );

    const jobs = await Job.find();
    res.json(jobs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

//mahesh code

//get job by id
exports.getJobById = async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job) return res.status(404).json({ error: "Job not found" });

    res.json(job);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

//delete job by id
exports.deleteJob = async (req, res) => {
  try {
    const job = await Job.findByIdAndDelete(req.params.id);
    if (!job) return res.status(404).json({ error: "Job not found" });

    res.json({ message: "Job deleted permanently" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
