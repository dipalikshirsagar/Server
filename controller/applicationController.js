const Application = require("../models/ApplicationSchema");
const Job = require("../models/JobSchema");
const User = require("../models/User");              
const Notification = require("../models/notificationSchema");

// CREATE APPLICATION
exports.createApplication = async (req, res) => {
  try {
    const job = await Job.findById(req.body.job);
    if (!job) return res.status(404).json({ message: "Job not found" });

    const { applicantType, employee, referredBy,name,
      email,
      phone,
      experience,
      city } = req.body;

    if (applicantType === "inhouse" && !["inhouse","both"].includes(job.jobType))
      return res.status(403).json({ message: "Inhouse applications not allowed" });

    if (applicantType === "referral" && !["referral","both"].includes(job.jobType))
      return res.status(403).json({ message: "Referral applications not allowed" });

    if (applicantType === "inhouse" && !employee)
      return res.status(400).json({ message: "Employee is required for inhouse" });

    if (applicantType === "referral" && (!email || !referredBy))
      return res.status(400).json({ message: "Candidate details & referredBy required" });

    let existingApp;

    if (applicantType === "inhouse") {
      existingApp = await Application.findOne({ job: job._id, employee });
    }

    if (applicantType === "referral") {
      existingApp = await Application.findOne({
        job: job._id,
        "email": email
      });
    }

    if (existingApp)
      return res.status(409).json({ message: "Already applied for this job" });
    const resume=req.files?.resumeUrl?.[0];
    const applicationData = {
      job: job._id,
      applicantType,
      employee: applicantType === "inhouse" ? employee : null,
      referredBy: applicantType === "referral" ? referredBy : null,
      candidate: {
        name,
        email,
        phone,
        experience,
        city,
        resumeUrl: req.files?.resumeUrl?.[0]?.path || ""
      },
      resumePublicId:resume?.filename
    };
    
    const app = await Application.create(applicationData );
    // added by shivani
    let applicantName;

      if (applicantType === "inhouse") {
        const employeeUser = await User.findById(employee).select("name");
        applicantName = employeeUser?.name || "Employee";
      } else {
        applicantName = name || "Candidate";
      }

      // Find HR, Admin, COO, CEO, MD
      const notifyUsers = await User.find(
        { role: { $in: ["hr", "admin", "coo", "ceo", "md"] } },
        "_id"
      );

      if (notifyUsers.length > 0) {
        const notifications = notifyUsers.map((user) => ({
          user: user._id,
          type: "Job Application",
          message: `${applicantName} applied for job: ${job.jobTitle}`,
          triggeredByRole: "EMPLOYEE",
          jobRef: job._id,
          isRead: false,
          createdAt: new Date(),
        }));

        await Notification.insertMany(notifications);
      }

    res.status(201).json(app);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};


// GET ALL APPLICATIONS
exports.getApplications = async (req, res) => {
  const apps = await Application.find()
    .populate("job", "jobTitle department")
    .populate("employee", "name email")
    .populate("referredBy", "name email");

  res.json(apps);
};

// GET APPLICATION BY ID
exports.getApplicationById = async (req, res) => {
  const app = await Application.findById(req.params.id)
    .populate("job")
    .populate("employee")
    .populate("referredBy");

  if (!app) return res.status(404).json({ message: "Application not found" });

  res.json(app);
};

// UPDATE STATUS
exports.updateApplication = async (req, res) => {
  const app = await Application.findByIdAndUpdate(
    req.params.id,
    { status: req.body.status },
    { new: true }
  );

  if (!app) return res.status(404).json({ message: "Application not found" });

  res.json(app);
};

// DELETE APPLICATION (HARD DELETE)
exports.deleteApplication = async (req, res) => {
  await Application.findByIdAndDelete(req.params.id);
  res.json({ message: "Application deleted" });
};

// GET APPLICATIONS BY JOB ID
exports.getApplicationsByJob = async (req, res) => {
  try {
    const { jobId } = req.params;

    const applications = await Application.find({ job: jobId })
      .populate("job", "jobTitle department")
      .populate("employee", "name email")
      .populate("referredBy", "name email");

    if (!applications.length) {
      return res.status(404).json({ message: "No applications found for this job" });
    }

    res.status(200).json(applications);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// exports.getApplicationsByEmployee = async (req, res) => {
//   try {
//     const { employeeId } = req.params;
//     const { applicantType } = req.query; // inhouse / referral

//     const filter = {
//       employee: employeeId
//     };

//     if (applicantType) {
//       filter.applicantType = applicantType;
//     }

//     const applications = await Application.find(filter)
//       .populate("job")
//       .populate("employee", "name email")
//       .sort({ createdAt: -1 });

//     res.status(200).json(applications);
//   } catch (err) {
//     console.error("getApplicationsByEmployee error:", err);
//     res.status(500).json({ message: "Failed to fetch applications" });
//   }
// };

exports.getApplicationsByEmployee = async (req, res) => {
  try {
    const { employeeId } = req.params;
    const { applicantType } = req.query; // inhouse / referral

    let filter = {};

    if (applicantType === "inhouse") {
      filter = {
        applicantType: "inhouse",
        employee: employeeId
      };
    } 
    else if (applicantType === "referral") {
      filter = {
        applicantType: "referral",
        referredBy: employeeId
      };
    } 
    else {
      // fallback → return all apps related to this employee
      filter = {
        $or: [
          { employee: employeeId },
          { referredBy: employeeId }
        ]
      };
    }

    const applications = await Application.find(filter)
      .populate("job")
      .populate("employee", "name email")
      .populate("referredBy", "name email")
      .sort({ createdAt: -1 })
      .lean();

    res.status(200).json(applications);
  } catch (err) {
    console.error("getApplicationsByEmployee error:", err);
    res.status(500).json({ message: "Failed to fetch applications" });
  }
};



exports.getResume = async (req, res) => {
  try {
    const publicId = `uploads/${req.params.publicId}`;

    const signedUrl = cloudinary.utils.private_download_url(
      publicId,
      "pdf",
      {
        resource_type: "raw",
        expires_at: Math.floor(Date.now() / 1000) + 60 * 5, // 5 min
      }
    );

    res.json({ url: signedUrl });
  } catch (err) {
    res.status(500).json({ message: "Failed to generate resume link" });
  }
};


