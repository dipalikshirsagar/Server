const Job = require("../models/JobSchema");

// CREATE JOB
exports.createJob = async (req, res) => {
  try {
    const { ctc, experience, noOfOpenings, dueOn } = req.body;

    if (ctc.min >= ctc.max)
      return res.status(400).json({ error: "CTC min must be less than max" });

    if (experience.min >= experience.max)
      return res.status(400).json({ error: "Experience min must be less than max" });

    if (noOfOpenings <= 0)
      return res.status(400).json({ error: "No of openings must be greater than 0" });

    if (new Date(dueOn) < new Date())
      return res.status(400).json({ error: "Due date must be in the future" });

    const job = await Job.create(req.body);
    res.status(201).json(job);

  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};


// UPDATE JOB
exports.updateJob = async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job) return res.status(404).json({ error: "Job not found" });

    const { ctc, experience, noOfOpenings, dueOn } = req.body;

    if (ctc && ctc.min >= ctc.max)
      return res.status(400).json({ error: "CTC min must be less than max" });

    if (experience && experience.min >= experience.max)
      return res.status(400).json({ error: "Experience min must be less than max" });

    if (noOfOpenings !== undefined && noOfOpenings <= 0)
      return res.status(400).json({ error: "No of openings must be greater than 0" });

    if (dueOn && new Date(dueOn) < new Date())
      return res.status(400).json({ error: "Due date must be in the future" });

    Object.assign(job, req.body);
    await job.save();

    res.json(job);

  } catch (err) {
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
exports.getAllJobs = async (req, res) => {
  try {
    const jobs = await Job.find();
    res.json(jobs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};


//get job by id
exports.getJobById = async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job)
      return res.status(404).json({ error: "Job not found" });

    res.json(job);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};


//delete job by id
exports.deleteJob = async (req, res) => {
  try {
    const job = await Job.findByIdAndDelete(req.params.id);
    if (!job)
      return res.status(404).json({ error: "Job not found" });

    res.json({ message: "Job deleted permanently" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};



