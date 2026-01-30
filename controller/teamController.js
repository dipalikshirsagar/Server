const Team = require("../models/TeamSchema");
const TaskNotification = require("../models/TaskNotificationSchema");
const Project = require("../models/ProjectSchema");

exports.createTeam = async (req, res) => {
  try {
    const project = await Project.findById(req.body.project).select("managers");

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project not found",
      });
    }

    if (!project.managers || project.managers.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Project has no manager assigned",
      });
    }

    const team = new Team({
      name: req.body.name,
      project: project._id,
      department: req.body.department,
      assignToProject: req.body.assignToProject || [],
      createdBy: req.body.createdBy,
    });

    await team.save();

    const savedTeam = await Team.findById(team._id)
      .populate("project", "_id name startDate endDate dueDate")
      .populate("assignToProject", "_id name")
      .populate("createdBy", "_id name");

    // -------------------------------------------------------
    const teamName = savedTeam.name;
    const projectName = savedTeam.project?.name;
    const teamMembers = savedTeam.assignToProject || [];
    const projectId = savedTeam.project?._id;

    try {
      const teamMessage = `You have been added to team "${teamName}" for project "${projectName}".`;

      for (const member of teamMembers) {
        await TaskNotification.create({
          user: member._id,
          type: "Team",
          message: teamMessage,
          taskRef: null,
          projectRef: projectId,
          isRead: false,
        });
      }
      console.log(`Notification sent to ${teamMembers.length} team members.`);

      const adminUsers = await User.find({
        role: { $in: ["admin", "hr", "ceo", "coo", "md"] },
      }).select("_id role");

      if (adminUsers.length > 0) {
        const adminMessage = `New team "${teamName}" has been created for project "${projectName}".`;

        for (const admin of adminUsers) {
          await TaskNotification.create({
            user: admin._id,
            type: "Team",
            message: adminMessage,
            taskRef: null,
            projectRef: projectId,
            isRead: false,
          });
        }
        console.log(`Notification sent to ${adminUsers.length} admin users.`);
      }
    } catch (error) {
      console.log("Error sending notifications", error);
    }
    // --------------------------------------------------------

    res.status(201).json({
      success: true,
      data: savedTeam,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

exports.getAllTeams = async (req, res) => {
  try {
    const teams = await Team.find({
      project: { $exists: true, $ne: null },
    })
      .populate({
        path: "project",
        match: { _id: { $exists: true } },
      })
      .populate("assignToProject", "_id name");

    const filteredTeams = teams.filter((team) => team.project !== null);

    res.status(200).json({
      success: true,
      data: filteredTeams,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

exports.getTeamById = async (req, res) => {
  try {
    const team = await Team.findById(req.params.id)
      .populate({
        path: "project",
        match: { _id: { $exists: true } },
      })
      .populate("assignToProject", "_id name");

    if (!team || !team.project) {
      return res.status(404).json({
        success: false,
        message: "Team not found or project not assigned",
      });
    }
    res.status(200).json({
      success: true,
      data: team,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

exports.updateTeam = async (req, res) => {
  try {
    const updatedTeam = await Team.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!updatedTeam) {
      return res.status(404).json({
        success: false,
        message: "Team not found",
      });
    }

    res.status(200).json({
      success: true,
      data: updatedTeam,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

exports.deleteTeam = async (req, res) => {
  try {
    const deletedTeam = await Team.findByIdAndDelete(req.params.id);

    if (!deletedTeam) {
      return res.status(404).json({
        success: false,
        message: "Team not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Team deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// exports.getTeamsByEmployeeId = async (req, res) => {
//   try {
//     const teams = await Team.find({
//       assignToProject: req.params.employeeId
//     })

//     .populate({
//         path: "project",
//         populate: {
//           path: "managers",
//           select: "name"
//         }
//       })
//      .populate("assignToProject", "_id name")

//     res.status(200).json({
//       success: true,
//       data: teams
//     });
//   } catch (error) {
//     res.status(500).json({
//       success: false,
//       message: error.message
//     });
//   }
// };

exports.getTeamsByEmployeeId = async (req, res) => {
  try {
    const teams = await Team.find({
      assignToProject: req.params.employeeId,
      project: { $exists: true, $ne: null },
    })
      .populate({
        path: "project",

        populate: {
          path: "managers",
          select: "name",
        },
      })
      .populate("assignToProject", "_id name");

    // ✅ remove orphaned projects (populate -> null)
    const filteredTeams = teams.filter((team) => team.project !== null);

    res.status(200).json({
      success: true,
      data: filteredTeams,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

const mongoose = require("mongoose");

exports.getTeamsCreatedByUserId = async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid User ID",
      });
    }

    const teams = await Team.find({
      createdBy: userId,
      project: { $exists: true, $ne: null },
    })
      .populate("project")
      .populate("assignToProject", "_id name")
      .sort({ createdAt: -1 });

    const filteredTeams = teams.filter((team) => team.project !== null);

    res.status(200).json({
      success: true,
      count: filteredTeams.length,
      data: filteredTeams,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
