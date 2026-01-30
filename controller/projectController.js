// const Project = require("../models/ProjectSchema");
// const User = require("../models/User")
// const TaskNotification = require("../models/TaskNotificationSchema")
// const Status = require("../models/StatusSchema")
// const mongoose = require("mongoose");
// exports.createProject = async (req, res) => {
//   try {
//     const {
//       name,
//       projectCode,
//       description,
//       managers,
//       assignedEmployees,
//       clientName,
//       startDate,
//       endDate,
//       dueDate,
//       status,
//       progressPercentage,
//       priority,
//       budget,
//       spendBudget,
//       category,
//       tags
//     } = req.body;

//     console.log("Project details:", req.body);

//     if (!name)
//       return res.status(400).json({ message: "Project name is required" });

//     if (!projectCode)
//       return res.status(400).json({ message: "Project code is required" });

//     if (!startDate)
//       return res.status(400).json({ message: "Start date is required" });

//     if (!endDate)
//       return res.status(400).json({ message: "End date is required" });

//     if (!priority)
//       return res.status(400).json({ message: "Priority is required" });

//     if (!managers || managers.length === 0)
//       return res.status(400).json({ message: "At least one manager is required" });

//     // UNIQUE Project Code
//     const existingProject = await Project.findOne({ projectCode });
//     if (existingProject)
//       return res.status(400).json({ message: "Project code already exists" });

//     // START DATE < END DATE
//     if (new Date(endDate) < new Date(startDate))
//       return res.status(400).json({ message: "End date must be >= start date" });

//     // DUE DATE >= END DATE
//     if (dueDate && new Date(dueDate) < new Date(endDate))
//       return res.status(400).json({ message: "Due date must be >= end date" });

//     // Progress 0–100
//     if (progressPercentage < 0 || progressPercentage > 100)
//       return res.status(400).json({ message: "Progress must be between 0 and 100" });

//     // Budget >= 0
//     if (budget < 0)
//       return res.status(400).json({ message: "Budget cannot be negative" });

//     // SpendBudget <= Budget
//     if (spendBudget && Number(spendBudget) > Number(budget))
//       return res.status(400).json({ message: "Spent budget cannot exceed total budget" });

//     // Allowed status values
//     if (!status) return res.status(400).json({ message: "Status is required" });

//     // Allowed priorities
//     const allowedPriorities = ["P1", "P2", "P3", "P4"];
//     if (!allowedPriorities.includes(priority))
//       return res.status(400).json({ message: "Invalid priority value" });

//     // Allowed categories
//     // const allowedCategories = ["internal", "external"];
//     // if (category && !allowedCategories.includes(category))
//     //   return res.status(400).json({ message: "Invalid category value" });

//     const newProject = await Project.create({
//       name,
//       projectCode: projectCode.toUpperCase(),
//       description,
//       managers,
//       assignedEmployees: assignedEmployees || [],
//       clientName,
//       startDate,
//       endDate,
//       dueDate,
//       status,
//       progressPercentage: progressPercentage || 0,
//       priority,
//       budget: budget || 0,
//       spendBudget: spendBudget || 0,
//       category: category || "internal",
//       tags: tags || [],
//       attachments: req.files?.attachments?.map(f => f.filename) || []
//     });
//     const newProjects = await Project.findById(newProject._id).populate("managers").populate("status");
//     console.log("new:", newProject);
//     try {

//       const allUsers = await User.find({
//         isDeleted: false
//       });

//       const notificationsToCreate = [];
//       // Ceo Notification
//       for (const user of allUsers) {
//         if (user.role === "ceo" &&  user.role === "coo"  && user.role === "md") {
//           notificationsToCreate.push({
//             user: user._id,
//             type: "Project_created",
//             message: `New project "${newProject.name}" (${newProject.projectCode}) has been created by Admin.`,
//             projectRef: newProject._id,
//             isRead: false
//           });
//         }
//       }
//       // HR NOTification
//       for (const user of allUsers) {
//         if (user.role === "hr") {
//           notificationsToCreate.push({
//             user: user._id,
//             type: "Project_created",
//             message: `New project "${newProject.name}" (${newProject.projectCode}) has been created by Admin`,
//             projectRef: newProject._id,
//             isRead: false
//           });
//         }
//       }

// // //added by Samiksha
// //       // MD Notification
// //       for (const user of allUsers) {
// //         if (user.role === "md") {
// //           notificationsToCreate.push({
// //             user: user._id,
// //             type: "Project_created",
// //             message: `New project "${newProject.name}" (${newProject.projectCode}) has been created by Admin.`,
// //             projectRef: newProject._id,
// //             isRead: false
// //           });
// //         }
// //       }
//       // Manager Notification
//       for (const managerId of newProject.managers) {
//         notificationsToCreate.push({
//           user: managerId,
//           type: "Project_Assigned",
//           message: `You have been assigned as manager for project "${newProject.name}"`,
//           projectRef: newProject._id,
//           isRead: false
//         });
//       }

//       if (notificationsToCreate.length > 0) {
//         await TaskNotification.insertMany(notificationsToCreate);
//         console.log(`Notifications sent to ${notificationsToCreate.length} users`);
//       }

//     } catch (error) {
//       console.log("error to send notification:", error);
//     }

//     return res.status(201).json({
//       message: "Project created successfully",
//       project: newProjects,
//     });

//   } catch (error) {
//     console.error("CREATE PROJECT ERROR:", error);
//     return res.status(500).json({ message: "Internal Server Error" });
//   }
// };

// exports.getProjects = async (req, res) => {
//   try {
//     const projects = await Project.find()
//       .populate("managers", "name email role")
//       .populate("assignedEmployees", "name email role")
//       .populate("status", "name");

//     res.status(200).json(projects);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// };

// exports.getProjectById = async (req, res) => {
//   try {
//     const project = await Project.findById(req.params.id)
//       .populate("managers", "name email role")
//       .populate("assignedEmployees", "name email role")
//       .populate("status", "name");

//     if (!project) {
//       return res.status(404).json({ message: "Project not found" });
//     }

//     res.status(200).json(project);
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// };

// exports.deleteProject = async (req, res) => {
//   try {
//     const projectId = req.params.id;

//     const project = await Project.findById(projectId);

//     if (!project) {
//       return res.status(404).json({ message: "Project not found" });
//     }

//   // ------------------------------------------
//   const projectName = project.name;
//   const projectCode = project.projectCode;
//   const projectManagers = project.managers || [];

//   await Project.findByIdAndDelete(projectId);

// // --------------------------------------------
//    if (project.attachments?.public_id) {
//           await cloudinary.uploader.destroy(project.attachments.public_id,
//           { resource_type: "raw" });
//    }

//   //  notification code------------------------------------
//   try{
//     const message = `Project "${projectName}" (${projectCode}) has been deleted by Admin.`

//     //manager
//     for (const managerId of projectManagers) {
//       await TaskNotification.create({
//         user: managerId,
//         type: "Project_deleted",
//         message: message,
//         projectRef: projectId,
//         isRead: false
//         });
//       }

//       //ceo
//      const ceo = await User.find({
//         role: { $in: ["ceo", "coo","md"] },
//         isDeleted: false
//       });

//       for (const ceoUser of ceo) {
//         await TaskNotification.create({
//           user: ceoUser._id,
//           type: "Project_deleted",
//           message: message,
//           projectRef: projectId,
//           isRead: false
//         });
//       }

//       // hr
//       const hr = await User.find({
//         role: "hr",
//         isDeleted: false
//       });

//       // //added by Samiksha
//       // // MD Notification
//       // for (const user of allUsers) {
//       //   if (user.role === "md") {
//       //     notificationsToCreate.push({
//       //       user: user._id,
//       //       type: "Project_created",
//       //       message: `New project "${newProject.name}" (${newProject.projectCode}) has been created by Admin.`,
//       //       projectRef: newProject._id,
//       //       isRead: false
//       //     });
//       //   }
//       // }

//       for (const hrUser of hr) {
//         await TaskNotification.create({
//           user: hrUser._id,
//           type: "Project_deleted",
//           message: message,
//           projectRef: projectId,
//           isRead: false
//         });
//       }
//     console.log(`notification send ${projectManagers.length} managers, ${ceo.length} ceo, ${md.length} md, ${hr.length}Hr.`)
//   }
//   catch(error){
//     console.log("error to send notification",error)
//   }
// // ---------------------------------------------------------

//   res.json({ message: "Project deleted successfully" });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// };

// exports.updateProject = async (req, res) => {
//   try {
//     const projectId = req.params.id;

//     const {
//       name,
//       projectCode,
//       description,
//       managers,
//       assignedEmployees,
//       clientName,
//       startDate,
//       endDate,
//       dueDate,
//       status,
//       progressPercentage,
//       priority,
//       budget,
//       spendBudget,
//       category,
//       tags,
//     } = req.body;

//     console.log("Update Project Body:", req.body);

//     if (projectCode) {
//       const existing = await Project.findOne({
//         projectCode: projectCode.toUpperCase(),
//         _id: { $ne: projectId },
//       });

//       if (existing)
//         return res.status(400).json({ message: "Project code already exists" });
//     }

//     const finalStartDate = startDate || undefined;
//     const finalEndDate = endDate || undefined;

//     if (finalStartDate && finalEndDate) {
//       if (new Date(finalEndDate) < new Date(finalStartDate)) {
//         return res.status(400).json({
//           message: "End date must be >= start date",
//         });
//       }
//     }
//     if (dueDate) {
//       const project = await Project.findById(projectId);
//       const endDateToCompare = endDate || project.endDate;

//       if (new Date(dueDate) < new Date(endDateToCompare)) {
//         return res.status(400).json({
//           message: "Due date must be >= end date",
//         });
//       }
//     }

//     if (
//       progressPercentage &&
//       (progressPercentage < 0 || progressPercentage > 100)
//     ) {
//       return res.status(400).json({
//         message: "Progress must be between 0 and 100",
//       });
//     }

//     if (budget && budget < 0) {
//       return res.status(400).json({
//         message: "Budget cannot be negative",
//       });
//     }

//     // SpendBudget <= Budget
//     if (spendBudget) {
//       const project = await Project.findById(projectId);
//       const finalBudget = budget || project.budget;

//       if (Number(spendBudget) > Number(finalBudget)) {
//         return res.status(400).json({
//           message: "Spent budget cannot exceed total budget",
//         });
//       }
//     }

//     // Allowed statuses
//     // const allowedStatuses = ["Active", "Completed", "On Hold", "Cancelled"];
//     // if (status && !allowedStatuses.includes(status)) {
//     //   return res.status(400).json({ message: "Invalid status value" });
//     // }
//     let statusName = null;
//     if (status) {
//       if (!mongoose.Types.ObjectId.isValid(status)) {
//         return res.status(400).json({
//           message: "Invalid Status ID"
//         });
//       }

//       const statusExists = await Status.findById(status);
//       if (!statusExists) {
//         return res.status(400).json({
//           message: "Status not found."
//         });
//       }
//       statusName = statusExists.name;
//     }

//     // Allowed priorities
//     const allowedPriorities = ["P1", "P2", "P3", "P4"];
//     if (priority && !allowedPriorities.includes(priority)) {
//       return res.status(400).json({ message: "Invalid priority value" });
//     }

//     // Allowed categories
//     const allowedCategories = ["internal", "external"];
//     if (category && !allowedCategories.includes(category)) {
//       return res.status(400).json({ message: "Invalid category value" });
//     }

//     const oldProject = await Project.findById(projectId).populate("status", "name");

//     const updateData = {
//       ...(name && { name }),
//       ...(projectCode && { projectCode: projectCode.toUpperCase() }),
//       ...(description && { description }),
//       ...(managers && { managers }),
//       ...(assignedEmployees && { assignedEmployees }),
//       ...(clientName && { clientName }),
//       ...(startDate && { startDate }),
//       ...(endDate && { endDate }),
//       ...(dueDate && { dueDate }),
//       ...(status && { status }),
//       ...(progressPercentage && { progressPercentage }),
//       ...(priority && { priority }),
//       ...(budget && { budget }),
//       ...(spendBudget && { spendBudget }),
//       ...(category && { category }),
//       ...(tags && { tags }),
//     };

//     // Update attachments
//     if (req.files?.attachments) {
//       updateData.attachments = req.files.attachments.map((f) => f.filename);
//     }

//     const updatedProject = await Project.findByIdAndUpdate(
//       projectId,
//       updateData,
//       { new: true }
//     ).populate("status", "name");

//     if (!updatedProject) {
//       return res.status(404).json({ message: "Project not found" });
//     }

//     // Notification code --------------------------------------
//     try {
//       const oldStatusName = oldProject.status?.name || oldProject.status;
//       const newStatusName = statusName || (status && updatedProject.status?.name);

//       const statusChanged = status && (oldStatusName !== newStatusName);

//       const priorityChanged = priority && (oldProject.priority !== priority);

//       if (statusChanged || priorityChanged) {

//         if (statusChanged && priorityChanged) {

//           for (const managerId of updatedProject.managers) {
//             await TaskNotification.create({
//               user: managerId,
//               type: "Project_update",
//               message: `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}" and priority changed from "${oldProject.priority}" to "${priority}"`,
//               projectRef: updatedProject._id,
//               isRead: false
//             });
//           }
//         }
//         else if (statusChanged) {

//           for (const managerId of updatedProject.managers) {
//             await TaskNotification.create({
//               user: managerId,
//               type: "Project_update",
//               message: `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}"`,
//               projectRef: updatedProject._id,
//               isRead: false
//             });
//           }
//         }
//         else if (priorityChanged) {

//           for (const managerId of updatedProject.managers) {
//             await TaskNotification.create({
//               user: managerId,
//               type: "Project_update",
//               message: `Project "${updatedProject.name}" priority changed from "${oldProject.priority}" to "${priority}"`,
//               projectRef: updatedProject._id,
//               isRead: false
//             });
//           }
//         }

//         // ceo
//         const allCeoUsers = await User.find({ role: { $in: ["ceo", "coo", "md"] }, isDeleted: false });
//         for (const ceoUser of allCeoUsers) {
//           await TaskNotification.create({
//             user: ceoUser._id,
//             type: "Project_update",
//             message: statusChanged && priorityChanged
//               ? `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}" and priority changed from "${oldProject.priority}" to "${priority}"`
//               : statusChanged
//                 ? `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}"`
//                 : `Project "${updatedProject.name}" priority changed from "${oldProject.priority}" to "${priority}"`,
//             projectRef: updatedProject._id,
//             isRead: false
//           });
//         }

//         // //added by Samiksha
//         // // md
//         // const allmdUsers = await User.find({ role: "md", isDeleted: false });
//         // for (const mdUser of allmdUsers) {
//         //   await TaskNotification.create({
//         //     user: mdUser._id,
//         //     type: "Project_update",
//         //     message: statusChanged && priorityChanged
//         //       ? `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}" and priority changed from "${oldProject.priority}" to "${priority}"`
//         //       : statusChanged
//         //         ? `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}"`
//         //         : `Project "${updatedProject.name}" priority changed from "${oldProject.priority}" to "${priority}"`,
//         //     projectRef: updatedProject._id,
//         //     isRead: false
//         //   });
//         // }

//         // hr
//         const allHrUsers = await User.find({ role: "hr", isDeleted: false });
//         for (const hrUser of allHrUsers) {
//           await TaskNotification.create({
//             user: hrUser._id,
//             type: "Project_update",
//             message: statusChanged && priorityChanged
//               ? `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}" and priority changed from "${oldProject.priority}" to "${priority}"`
//               : statusChanged
//                 ? `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}"`
//                 : `Project "${updatedProject.name}" priority changed from "${oldProject.priority}" to "${priority}"`,
//             projectRef: updatedProject._id,
//             isRead: false
//           });
//         }
//       }
//       console.log("Notification sent successfully");
//     } catch (error) {
//       console.log("Error sending notification:", error);
//     }

//     return res.status(200).json({
//       message: "Project updated successfully",
//       project: updatedProject,
//     });

//   } catch (error) {
//     console.error("UPDATE PROJECT ERROR:", error);
//     return res.status(500).json({ message: "Internal Server Error" });
//   }
// };

// // exports.getUniqueProjectNames = async (req, res) => {
// //   try {
// //     const names = await Project.distinct("name");

// //     return res.status(200).json({
// //       success: true,
// //       projects: names,
// //     });
// //   } catch (error) {
// //     console.error("Error fetching unique projects:", error);
// //     return res.status(500).json({ message: "Internal Server Error" });
// //   }
// // };

// exports.getUniqueProjectNames = async (req, res) => {
//   try {
//     const { managerId } = req.params;

//     if (!mongoose.Types.ObjectId.isValid(managerId)) {
//       return res.status(400).json({
//         success: false,
//         message: "Invalid Manager ID",
//       });
//     }

//     const managerObjectId = new mongoose.Types.ObjectId(managerId);

//     const projects = await Project.find(
//       { managers: { $in: [managerObjectId] } },
//       { name: 1, _id: 0 }
//     );

//     const uniqueNames = [...new Set(projects.map(p => p.name))];

//     return res.status(200).json({
//       success: true,
//       projects: uniqueNames,
//     });

//   } catch (error) {
//     console.error("Error fetching unique projects:", error);
//     return res.status(500).json({
//       success: false,
//       message: error.message,
//     });
//   }
// };

// exports.getProjectsByManager = async (req, res) => {
//   try {
//     const { managerId } = req.params;

//     const projects = await Project.find({
//       managers: managerId,
//     })
//       .populate("status", "name")
//       .select("_id name projectCode clientName description dueDate endDate startDate assignedEmployees")
//       .sort({ createdAt: -1 });

//     res.status(200).json({
//       success: true,
//       data: projects,
//     });
//   } catch (error) {
//     res.status(500).json({
//       success: false,
//       message: error.message,
//     });
//   }
// };

// exports.updateProjectStatusByManager = async (req, res) => {
//   try {
//     const projectId = req.params.id;
//     const { status } = req.body;

//     if (!mongoose.Types.ObjectId.isValid(projectId)) {
//       return res.status(400).json({ message: "Invalid Project ID" });
//     }

//     if (!mongoose.Types.ObjectId.isValid(status)) {
//       return res.status(400).json({ message: "Invalid Status ID" });
//     }

//     const statusExists = await Status.findById(status);
//     if (!statusExists) {
//       return res.status(404).json({ message: "Status not found" });
//     }

//     const oldProject = await Project.findById(projectId).populate("status", "_id name");
//     if (!oldProject) {
//       return res.status(404).json({ message: "Project not found" });
//     }

//     const updatedProject = await Project.findByIdAndUpdate(
//       projectId,
//       { status },
//       { new: true }
//     ).populate("status", "_id name");

//     if (oldProject.status?.name !== statusExists.name) {
//       const managers = updatedProject.managers || [];

//       for (const managerId of managers) {
//         await TaskNotification.create({
//           user: managerId,
//           type: "Project_update",
//           message: `Project "${updatedProject.name}" status changed from "${oldProject.status?.name}" to "${statusExists.name}"`,
//           projectRef: updatedProject._id,
//           isRead: false,
//         });
//       }
//     }

//     return res.status(200).json({
//       message: "Project status updated successfully",
//       project: updatedProject,
//     });

//   } catch (error) {
//     console.error("UPDATE PROJECT STATUS ERROR:", error);
//     return res.status(500).json({ message: error.message || "Internal Server Error" });
//   }
// };

//Komal project update
const Project = require("../models/ProjectSchema");
const User = require("../models/User");
const TaskNotification = require("../models/TaskNotificationSchema");
const Status = require("../models/StatusSchema");
const mongoose = require("mongoose");

exports.createProject = async (req, res) => {
  try {
    const {
      name,
      projectCode,
      description,
      managers,
      assignedEmployees,
      clientName,
      startDate,
      endDate,
      dueDate,
      progressPercentage,
      priority,
      budget,
      spendBudget,
      category,
      tags,
    } = req.body;

    console.log("Project details:", req.body);

    if (!name)
      return res.status(400).json({ message: "Project name is required" });

    if (!projectCode)
      return res.status(400).json({ message: "Project code is required" });

    if (!startDate)
      return res.status(400).json({ message: "Start date is required" });

    // if (!endDate)
    //   return res.status(400).json({ message: "End date is required" });

    if (!priority)
      return res.status(400).json({ message: "Priority is required" });

    if (!managers || managers.length === 0)
      return res
        .status(400)
        .json({ message: "At least one manager is required" });

    // UNIQUE Project Code
    const existingProject = await Project.findOne({ projectCode });
    if (existingProject)
      return res.status(400).json({ message: "Project code already exists" });

    // START DATE < END DATE
    if (new Date(endDate) < new Date(startDate))
      return res
        .status(400)
        .json({ message: "End date must be >= start date" });

    // DUE DATE >= END DATE
    if (dueDate && new Date(dueDate) < new Date(endDate))
      return res.status(400).json({ message: "Due date must be >= end date" });

    // Progress 0–100
    if (progressPercentage < 0 || progressPercentage > 100)
      return res
        .status(400)
        .json({ message: "Progress must be between 0 and 100" });

    // Budget >= 0
    if (budget < 0)
      return res.status(400).json({ message: "Budget cannot be negative" });

    // SpendBudget <= Budget
    if (spendBudget && Number(spendBudget) > Number(budget))
      return res
        .status(400)
        .json({ message: "Spent budget cannot exceed total budget" });

    // Allowed priorities
    const allowedPriorities = ["P1", "P2", "P3", "p4"];
    if (!allowedPriorities.includes(priority))
      return res.status(400).json({ message: "Invalid priority value" });

    // Allowed categories
    // const allowedCategories = ["internal", "external"];
    // if (category && !allowedCategories.includes(category))
    //   return res.status(400).json({ message: "Invalid category value" });

    const newProject = await Project.create({
      name,
      projectCode: projectCode.toUpperCase(),
      description,
      managers,
      assignedEmployees: assignedEmployees || [],
      clientName,
      startDate,
      endDate,
      dueDate,
      progressPercentage: progressPercentage || 0,
      priority,
      budget: budget || 0,
      spendBudget: spendBudget || 0,
      category: category || "internal",
      tags: tags || [],
      attachments: req.files?.attachments?.map((f) => f.filename) || [],
    });
    const newProjects = await Project.findById(newProject._id).populate(
      "managers",
    );
    console.log("new:", newProject);
    try {
      const allUsers = await User.find({
        isDeleted: false,
      });

      const notificationsToCreate = [];
      // Ceo Notification
      for (const user of allUsers) {
        if (user.role === "ceo") {
          notificationsToCreate.push({
            user: user._id,
            type: "Project_created",
            message: `New project "${newProject.name}" (${newProject.projectCode}) has been created by Admin.`,
            projectRef: newProject._id,
            isRead: false,
          });
        }
      }
      // HR NOTification
      for (const user of allUsers) {
        if (user.role === "hr") {
          notificationsToCreate.push({
            user: user._id,
            type: "Project_created",
            message: `New project "${newProject.name}" (${newProject.projectCode}) has been created by Admin`,
            projectRef: newProject._id,
            isRead: false,
          });
        }
      }
      // Manager Notification
      for (const managerId of newProject.managers) {
        notificationsToCreate.push({
          user: managerId,
          type: "Project_Assigned",
          message: `You have been assigned as manager for project "${newProject.name}"`,
          projectRef: newProject._id,
          isRead: false,
        });
      }

      if (notificationsToCreate.length > 0) {
        await TaskNotification.insertMany(notificationsToCreate);
        console.log(
          `Notifications sent to ${notificationsToCreate.length} users`,
        );
      }
    } catch (error) {
      console.log("error to send notification:", error);
    }

    return res.status(201).json({
      message: "Project created successfully",
      project: newProjects,
    });
  } catch (error) {
    console.error("CREATE PROJECT ERROR:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

exports.getProjects = async (req, res) => {
  try {
    const projects = await Project.find()
      .sort({ createdAt: -1 })
      .populate("managers", "name email role")
      .populate("assignedEmployees", "name email role")
      .populate("manualStatusUpdatedBy", "name role");

    res.status(200).json(projects);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.getProjectById = async (req, res) => {
  try {
    const project = await Project.findById(req.params.id)
      .populate("managers", "name email role")
      .populate("assignedEmployees", "name email role");

    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    res.status(200).json(project);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.deleteProject = async (req, res) => {
  try {
    const projectId = req.params.id;

    const project = await Project.findById(projectId);

    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    // ------------------------------------------
    const projectName = project.name;
    const projectCode = project.projectCode;
    const projectManagers = project.managers || [];

    await Project.findByIdAndDelete(projectId);

    // --------------------------------------------
    if (project.attachments?.public_id) {
      await cloudinary.uploader.destroy(project.attachments.public_id, {
        resource_type: "raw",
      });
    }

    //  notification code------------------------------------
    try {
      const message = `Project "${projectName}" (${projectCode}) has been deleted by Admin.`;

      //manager
      for (const managerId of projectManagers) {
        await TaskNotification.create({
          user: managerId,
          type: "Project_deleted",
          message: message,
          projectRef: projectId,
          isRead: false,
        });
      }

      //ceo
      const ceo = await User.find({
        role: "ceo",
        isDeleted: false,
      });

      for (const ceoUser of ceo) {
        await TaskNotification.create({
          user: ceoUser._id,
          type: "Project_deleted",
          message: message,
          projectRef: projectId,
          isRead: false,
        });
      }

      // hr
      const hr = await User.find({
        role: "hr",
        isDeleted: false,
      });

      for (const hrUser of hr) {
        await TaskNotification.create({
          user: hrUser._id,
          type: "Project_deleted",
          message: message,
          projectRef: projectId,
          isRead: false,
        });
      }
      console.log(
        `notification send ${projectManagers.length} managers, ${ceo.length} ceo, ${hr.length}Hr.`,
      );
    } catch (error) {
      console.log("error to send notification", error);
    }
    // ---------------------------------------------------------

    res.json({ message: "Project deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.updateProject = async (req, res) => {
  try {
    const projectId = req.params.id;

    const {
      name,
      projectCode,
      description,
      managers,
      assignedEmployees,
      clientName,
      startDate,
      endDate,
      dueDate,
      progressPercentage,
      priority,
      budget,
      spendBudget,
      category,
      tags,
    } = req.body;

    console.log("Update Project Body:", req.body);

    if (projectCode) {
      const existing = await Project.findOne({
        projectCode: projectCode.toUpperCase(),
        _id: { $ne: projectId },
      });

      if (existing)
        return res.status(400).json({ message: "Project code already exists" });
    }

    const finalStartDate = startDate || undefined;
    const finalEndDate = endDate || undefined;

    if (finalStartDate && finalEndDate) {
      if (new Date(finalEndDate) < new Date(finalStartDate)) {
        return res.status(400).json({
          message: "End date must be >= start date",
        });
      }
    }
    if (dueDate) {
      const project = await Project.findById(projectId);
      const endDateToCompare = endDate || project.endDate;

      if (new Date(dueDate) < new Date(endDateToCompare)) {
        return res.status(400).json({
          message: "Due date must be >= end date",
        });
      }
    }

    if (
      progressPercentage &&
      (progressPercentage < 0 || progressPercentage > 100)
    ) {
      return res.status(400).json({
        message: "Progress must be between 0 and 100",
      });
    }

    if (budget && budget < 0) {
      return res.status(400).json({
        message: "Budget cannot be negative",
      });
    }

    // SpendBudget <= Budget
    if (spendBudget) {
      const project = await Project.findById(projectId);
      const finalBudget = budget || project.budget;

      if (Number(spendBudget) > Number(finalBudget)) {
        return res.status(400).json({
          message: "Spent budget cannot exceed total budget",
        });
      }
    }

    // Allowed priorities
    const allowedPriorities = ["P1", "P2", "P3", "p4"];
    if (priority && !allowedPriorities.includes(priority)) {
      return res.status(400).json({ message: "Invalid priority value" });
    }

    // Allowed categories
    const allowedCategories = ["internal", "external"];
    if (category && !allowedCategories.includes(category)) {
      return res.status(400).json({ message: "Invalid category value" });
    }

    const oldProject = await Project.findById(projectId);

    const updateData = {
      ...(name && { name }),
      ...(projectCode && { projectCode: projectCode.toUpperCase() }),
      ...(description && { description }),
      ...(managers && { managers }),
      ...(assignedEmployees && { assignedEmployees }),
      ...(clientName && { clientName }),
      ...(startDate && { startDate }),
      ...(endDate && { endDate }),
      ...(dueDate && { dueDate }),
      ...(progressPercentage && { progressPercentage }),
      ...(priority && { priority }),
      ...(budget && { budget }),
      ...(spendBudget && { spendBudget }),
      ...(category && { category }),
      ...(tags && { tags }),
    };

    // Update attachments
    if (req.files?.attachments) {
      updateData.attachments = req.files.attachments.map((f) => f.filename);
    }

    const updatedProject = await Project.findByIdAndUpdate(
      projectId,
      updateData,
      { new: true },
    );

    if (!updatedProject) {
      return res.status(404).json({ message: "Project not found" });
    }

    // Notification code --------------------------------------
    try {
      const priorityChanged = priority && oldProject.priority !== priority;

      if (priorityChanged) {
        for (const managerId of updatedProject.managers) {
          await TaskNotification.create({
            user: managerId,
            type: "Project_update",
            message: `Project "${updatedProject.name}"  priority changed from "${oldProject.priority}" to "${priority}"`,
            projectRef: updatedProject._id,
            isRead: false,
          });
        }
        // ceo
        const allCeoUsers = await User.find({ role: "ceo", isDeleted: false });
        for (const ceoUser of allCeoUsers) {
          await TaskNotification.create({
            user: ceoUser._id,
            type: "Project_update",
            message: `Project "${updatedProject.name}" priority changed from "${oldProject.priority}" to "${priority}"`,
            projectRef: updatedProject._id,
            isRead: false,
          });
        }

        // hr
        const allHrUsers = await User.find({ role: "hr", isDeleted: false });
        for (const hrUser of allHrUsers) {
          await TaskNotification.create({
            user: hrUser._id,
            type: "Project_update",
            message: `Project "${updatedProject.name}" priority changed from "${oldProject.priority}" to "${priority}"`,
            projectRef: updatedProject._id,
            isRead: false,
          });
        }
      }
      console.log("Notification sent successfully");
    } catch (error) {
      console.log("Error sending notification:", error);
    }

    return res.status(200).json({
      message: "Project updated successfully",
      project: updatedProject,
    });
  } catch (error) {
    console.error("UPDATE PROJECT ERROR:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

exports.getUniqueProjectNames = async (req, res) => {
  try {
    const { managerId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(managerId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid Manager ID",
      });
    }

    const managerObjectId = new mongoose.Types.ObjectId(managerId);
    const projects = await Project.find(
      {
        managers: { $in: [managerObjectId] },
        manualStatus: { $nin: ["Completed", "Cancelled"] },
      },
      { name: 1, _id: 0 },
    );

    const uniqueNames = [...new Set(projects.map((p) => p.name))];

    return res.status(200).json({
      success: true,
      projects: uniqueNames,
    });
  } catch (error) {
    console.error("Error fetching unique projects:", error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

exports.getProjectsByManager = async (req, res) => {
  try {
    const { managerId } = req.params;

    const projects = await Project.find({
      managers: managerId,
    }).sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      data: projects,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

exports.updateProjectStatusByManager = async (req, res) => {
  try {
    const projectId = req.params.id;
    const { status } = req.body;

    if (!mongoose.Types.ObjectId.isValid(projectId)) {
      return res.status(400).json({ message: "Invalid Project ID" });
    }

    if (!mongoose.Types.ObjectId.isValid(status)) {
      return res.status(400).json({ message: "Invalid Status ID" });
    }

    const statusExists = await Status.findById(status);
    if (!statusExists) {
      return res.status(404).json({ message: "Status not found" });
    }

    const oldProject = await Project.findById(projectId).populate(
      "status",
      "_id name",
    );
    if (!oldProject) {
      return res.status(404).json({ message: "Project not found" });
    }

    const updatedProject = await Project.findByIdAndUpdate(
      projectId,
      { status },
      { new: true },
    ).populate("status", "_id name");

    if (oldProject.status?.name !== statusExists.name) {
      const managers = updatedProject.managers || [];

      for (const managerId of managers) {
        await TaskNotification.create({
          user: managerId,
          type: "Project_update",
          message: `Project "${updatedProject.name}" status changed from "${oldProject.status?.name}" to "${statusExists.name}"`,
          projectRef: updatedProject._id,
          isRead: false,
        });
      }
    }

    return res.status(200).json({
      message: "Project status updated successfully",
      project: updatedProject,
    });
  } catch (error) {
    console.error("UPDATE PROJECT STATUS ERROR:", error);
    return res
      .status(500)
      .json({ message: error.message || "Internal Server Error" });
  }
};

// exports.completeProject = async (req,res)=>{
//   const project = await Project.findById(req.params.id);
//   const oldStatusName = project.status;
//   project.manualStatus = "Completed";

//     project.manualStatusUpdatedAt = new Date();

//   const updatedProject=await project.save();
//    try {
//       const newStatusName = "Completed";
//       const statusChanged=true;

//       if (statusChanged) {
//           for (const managerId of updatedProject.managers) {
//             await TaskNotification.create({
//               user: managerId,
//               type: "Project_update",
//               message: `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}"`,
//               projectRef: updatedProject._id,
//               isRead: false
//             });
//           }

//         // ceo
//         const allCeoUsers = await User.find({ role: "ceo", isDeleted: false });
//         for (const ceoUser of allCeoUsers) {
//           await TaskNotification.create({
//             user: ceoUser._id,
//             type: "Project_update",
//             message: `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}"`,
//             projectRef: updatedProject._id,
//             isRead: false
//           });
//         }

//         // hr
//         const allHrUsers = await User.find({ role: "hr", isDeleted: false });
//         for (const hrUser of allHrUsers) {
//           await TaskNotification.create({
//             user: hrUser._id,
//             type: "Project_update",
//             message: `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}"`,
//             projectRef: updatedProject._id,
//             isRead: false
//           });
//         }
//       }
//       console.log("Notification sent successfully");
//     } catch (error) {
//       console.log("Error sending notification:", error);
//     }
//   res.json(project);
// };

exports.completeProject = async (req, res) => {
  const { updatedBy } = req.body;

  const project = await Project.findById(req.params.id);

  project.manualStatus = "Completed";
  project.manualStatusUpdatedBy = updatedBy || null;
  project.manualStatusUpdatedAt = new Date();

  await project.save();

  return res.json(project);
};

// exports.cancelProject = async (req,res)=>{
//   const project = await Project.findById(req.params.id);
//   const updatedProject=project.manualStatus = "Cancelled";

//       project.manualStatusUpdatedBy = req.user._id; //manager id
//     project.manualStatusUpdatedAt = new Date();

//   await project.save();
//    try {
//       const oldStatusName = project.status;
//       const newStatusName =  "Cancelled";
//       const statusChanged=true;

//       if (statusChanged) {
//           for (const managerId of updatedProject.managers) {
//             await TaskNotification.create({
//               user: managerId,
//               type: "Project_update",
//               message: `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}"`,
//               projectRef: updatedProject._id,
//               isRead: false
//             });
//           }

//         // ceo
//         const allCeoUsers = await User.find({ role: "ceo", isDeleted: false });
//         for (const ceoUser of allCeoUsers) {
//           await TaskNotification.create({
//             user: ceoUser._id,
//             type: "Project_update",
//             message: `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}"`,
//             projectRef: updatedProject._id,
//             isRead: false
//           });
//         }

//         // hr
//         const allHrUsers = await User.find({ role: "hr", isDeleted: false });
//         for (const hrUser of allHrUsers) {
//           await TaskNotification.create({
//             user: hrUser._id,
//             type: "Project_update",
//             message: `Project "${updatedProject.name}" status changed from "${oldStatusName}" to "${newStatusName}"`,
//             projectRef: updatedProject._id,
//             isRead: false
//           });
//         }
//       }
//       console.log("Notification sent successfully");
//     } catch (error) {
//       console.log("Error sending notification:", error);
//     }
//   res.json(project);
// };

// admin can update status manually

exports.cancelProject = async (req, res) => {
  const { updatedBy } = req.body;

  const project = await Project.findById(req.params.id);

  project.manualStatus = "Cancelled";
  project.manualStatusUpdatedBy = updatedBy || null;
  project.manualStatusUpdatedAt = new Date();

  await project.save();

  return res.json(project);
};

exports.updateManualStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body; // "Completed" | "Cancelled"

    if (!["Completed", "Cancelled"].includes(status)) {
      return res.status(400).json({ message: "Invalid status" });
    }

    const project = await Project.findById(id);
    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    const oldStatus = project.status; // virtual
    project.manualStatus = status;

    await project.save();

    // 🔔 Notifications (reuse your logic)
    const managers = project.managers || [];
    for (const managerId of managers) {
      await TaskNotification.create({
        user: managerId,
        type: "Project_update",
        message: `Project "${project.name}" status changed from "${oldStatus}" to "${status}"`,
        projectRef: project._id,
        isRead: false,
      });
    }

    return res.status(200).json({
      success: true,
      message: "Project status updated",
      project,
    });
  } catch (error) {
    console.error("MANUAL STATUS ERROR:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
