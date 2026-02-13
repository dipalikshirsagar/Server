const express = require("express");
const multer = require("multer");
const mongoose = require("mongoose");
const Ticket = require("../models/Ticket");
const User = require("../models/User");
const Notification = require("../models/notificationSchema");

const router = express.Router();

/* ========= FILE UPLOAD ========= */
const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => cb(null, Date.now() + "_" + file.originalname),
});
const upload = multer({ storage });

/* ================= CREATE TICKET ================= */
//  router.post("/",upload.array("attachment", 5), async (req, res) => {
//   try {
//     const {category, priority, description } = req.body;

//     if (!category || !priority) {
//       return res.status(400).json({ message: "Missing required fields" });
//     }
// // ✅ LOGGED-IN USER ID (JWT middleware असणे गरजेचे)
//     const employeeId = req.user?._id;
//     if (!employeeId) {
//       return res.status(401).json({ message: "Unauthorized user" });
//     }

//   try {
//     const { employeeName, category, priority, description } = req.body;

//     if ( !category || !priority) {
//       return res.status(400).json({ message: "Missing required fields" });
//     }

//     // Generate ticket number
//     const lastTicket = await Ticket.findOne().sort({ createdAt: -1 });
//     const nextNumber = lastTicket?.ticketId
//       ? parseInt(lastTicket.ticketId.split("-")[1]) + 1
//       : 1;

//     const attachments = req.files?.map(f => f.filename) || [];

//     const ticket = await Ticket.create({
//       ticketId: `TKT-${nextNumber}`,
//        employeeName,
//       category,
//       priority,
//       description,
//      attachment: attachments,
//       status: "Open",
//       assignedTo: "IT Support",
//       comments: [],

//     });

// // Notify IT Support users
// const itUsers = await User.find({ role: "IT_SUPPORT" });

// if (itUsers.length) {
//   await Notification.insertMany(
//     itUsers.map(it => ({
//       user: it._id,
//       type: "Ticket",
//       message: `New ticket raised by ${employeeName}`,
//       ticketRef: ticket._id,
//     }))
//   );

//   console.log("🔔 Notification created successfully");
// } else {
//   console.log("⚠ No IT Support users found to notify");
// }

//     // 📧 Email
//     // await sendNewTicketMail(ticket);

//     res.status(201).json(ticket);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: "Ticket creation failed" });
//   }
// });
router.post("/", upload.array("attachment", 5), async (req, res) => {
  try {
    const { employeeName, category, priority, description } = req.body;

    if (!employeeName || !category || !priority) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // 🔐 Logged-in user (recommended)
    const employeeId = req.user?._id; // JWT middleware required

    // Generate ticket number
    const lastTicket = await Ticket.findOne()
      .sort({ createdAt: -1 })
      .populate("employeeName");
    const nextNumber = lastTicket
      ? parseInt(lastTicket.ticketId.split("-")[1]) + 1
      : 1;

    const attachments = req.files?.map((f) => f.filename) || [];

    const ticket = await Ticket.create({
      ticketId: `TKT-${nextNumber}`,
      employee: employeeId, // ✅ IMPORTANT
      employeeName,
      category,
      priority,
      description,
      attachment: attachments,
      status: "Open",
      assignedTo: "IT_Support",
    });

    /* ================= NOTIFICATION ================= */

    // 🔔 Notify IT Support (MATCH ROLE EXACTLY)
    const itUsers = await User.find({
      role: { $in: ["IT_Support"] }, // adjust as per DB
    });

    if (itUsers.length) {
      await Notification.insertMany(
        itUsers.map((it) => ({
          user: it._id,
          type: "Ticket",
          ticketRef: ticket._id,
          //snehal added 16-01-2026
          triggeredByRole: "EMPLOYEE",
          //snehal added 16-01-2026
          message: `New ticket raised by ${employeeName}`,
        })),
      );
    }

    res.status(201).json(ticket);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Ticket creation failed" });
  }
});

/* ================= GET ALL ================= */
router.get("/", async (req, res) => {
  try {
    const tickets = await Ticket.find().sort({ raisedDate: -1 });
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch tickets" });
  }
});

/* ================= FILTER ================= */
router.get("/filter", async (req, res) => {
  try {
    const { status, from, to } = req.query;
    const query = {};

    if (status && status !== "All") query.status = status;
    if (from || to) {
      query.raisedDate = {};
      if (from) query.raisedDate.$gte = new Date(from);
      if (to) query.raisedDate.$lte = new Date(to);
    }

    const tickets = await Ticket.find(query).sort({ raisedDate: -1 });
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ message: "Failed to filter tickets" });
  }
});

/* ================= GET ONE ================= */
router.get("/:id", async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: "Invalid Ticket ID" });

    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ message: "Ticket not found" });

    ticket.attachment = Array.isArray(ticket.attachment)
      ? ticket.attachment
      : [];

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch ticket" });
  }
});

/* ================= UPDATE ================= */
router.put("/:id", upload.array("attachment", 5), async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ message: "Ticket not found" });

    //added snehal 16-01-2026
    let notifyEmployee = false;
    let messages = [];
    //snehal added 16-01-2026
    // Status change notification
    if (req.body.status && req.body.status !== ticket.status) {
      //snehal added 16-01-2026
      ticket.status = req.body.status;
      notifyEmployee = true;
      messages.push(`status changed to ${req.body.status}`);
      //snehal added 16-01-2026

      if (req.body.status === "Closed") {
        ticket.closedDate = new Date();
      }
    }
    // 🔄 Assigned change
    //snehal added 16-01-2026
    if (req.body.assignedTo && req.body.assignedTo !== ticket.assignedTo) {
      ticket.assignedTo = req.body.assignedTo;
      notifyEmployee = true;
      messages.push(`assigned to ${req.body.assignedTo}`);
    }
    //snehal added 16-01-2026
    // ✅ ONLY ALLOWED FIELDS
    ticket.category = req.body.category ?? ticket.category;
    ticket.priority = req.body.priority ?? ticket.priority;
    ticket.description = req.body.description ?? ticket.description;
    ticket.status = req.body.status ?? ticket.status;

    // Attachments (only once)
    if (req.files?.length) {
      ticket.attachment.push(...req.files.map((f) => f.filename));
    }

    await ticket.save();
    //snehal added 16-01-2026
    //🔔 🔥 CREATE EMPLOYEE NOTIFICATION
    if (notifyEmployee && ticket.employee) {
      await Notification.create({
        user: ticket.employee,
        type: "Ticket",
        ticketRef: ticket._id,
        triggeredByRole: "IT_Support",
        message: `IT Support updated your ticket (${ticket.ticketId}): ${messages.join(", ")}`,
      });
    }

    //snehal added 16-01-2026

    res.json(ticket);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to update ticket" });
  }
});

/* ================= DELETE ================= */
router.delete("/:id", async (req, res) => {
  try {
    const ticketId = req.params.id;

    const ticket = await Ticket.findById(ticketId);
    if (!ticket) return res.status(404).json({ message: "Ticket not found" });

    // 1️⃣ Delete Ticket
    await Ticket.findByIdAndDelete(ticketId);

    // 2️⃣ Delete ALL notifications related to this ticket
    await Notification.deleteMany({ ticketRef: ticketId });

    res.json({ message: "Ticket and notifications deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Delete failed" });
  }
});

/* ================= ADD COMMENT ================= */
// router.post("/:id/comment", async (req, res) => {
//   try {
//     const { message, role } = req.body;

//     const ticket = await Ticket.findById(req.params.id);
//     if (!ticket) return res.status(404).json({ message: "Ticket not found" });

//     ticket.comments.push({ message, role });

//     if (role === "IT") {
//       if (ticket.employee) {
//         await Notification.create({
//           user: ticket.employee,
//           type: "Ticket",
//           ticketRef: ticket._id,
//           message: `IT Support commented on your ticket (${ticket.ticketId})`,
//         });
//       }
//     } else {
//       const itUsers = await User.find({ role: "IT" });
//       if (itUsers.length) {
//         await Notification.insertMany(
//           itUsers.map(it => ({
//             user: it._id,
//             type: "Ticket",
//             ticketRef: ticket._id,
//             message: `${ticket.employeeName} commented on ticket (${ticket.ticketId})`,
//           }))
//         );
//       }
//     }

//     await ticket.save();
//     res.json(ticket);
//   } catch (err) {
//     res.status(500).json({ message: "Failed to add comment" });
//   }
// });
router.post("/:id/comment", async (req, res) => {
  try {
    const { message, role } = req.body;

    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ message: "Ticket not found" });

    ticket.comments.push({ message, role });

    // IT commented → notify employee
    if (role === "IT_Support" && ticket.employee) {
      await Notification.create({
        user: ticket.employee,
        type: "Ticket",
        ticketRef: ticket._id,
        //snehal added 16-01-2026
        triggeredByRole: "IT_Support",
        //snehal added 16-01-2026
        message: `IT Support commented on your ticket (${ticket.ticketId})`,
      });
    }

    // Employee commented → notify IT
    // else {
    //   const itUsers = await User.find({ role: "IT_Support" });
    //   await Notification.insertMany(
    //     itUsers.map(it => ({

    //       user: it._id ,
    //       type: "Ticket",
    //       ticketRef: ticket._id,
    //           //snehal added 16-01-2026
    //       triggeredByRole: "EMPLOYEE",
    //           //snehal added 16-01-2026
    //       message: `${ticket.employeeName} commented on ticket (${ticket.ticketId})`,
    //     }))
    //   );
    // }
    //added 16-01-2026
    // 🔔 Employee → IT
    if (role === "EMPLOYEE") {
      const itUsers = await User.find({ role: "IT_Support" });

      await Notification.insertMany(
        itUsers.map((it) => ({
          user: it._id,
          type: "Ticket",
          ticketRef: ticket._id,
          triggeredByRole: "EMPLOYEE",
          message: `${ticket.employeeName} commented on ticket (${ticket.ticketId})`,
        })),
      );
    }

    await ticket.save();
    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: "Failed to add comment" });
  }
});

/* ================= COMMENT READ ================= */
router.put("/:ticketId/comment/:commentId/read", async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.ticketId);
    if (!ticket) return res.status(404).json({ message: "Ticket not found" });

    const comment = ticket.comments.id(req.params.commentId);
    if (comment) comment.isRead = true;

    await ticket.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Failed to mark comment read" });
  }
});

// // ----------------added notification for IT support snehal------------
// router.get("/:id", async (req, res) => {
//   try {
//     const notifications = await Notification.find({
//       user: req.params.userId,
//     })
//       .populate("ticketRef", "ticketId")
//       .sort({ createdAt: -1 });

//     res.json(notifications);
//   } catch (err) {
//     res.status(500).json({ message: "Failed to fetch notifications" });
//   }
// });
router.get("/notifications/:userId", async (req, res) => {
  const notifications = await Notification.find({
    user: req.params.userId,
  })
    .populate("ticketRef", "ticketId")
    .sort({ createdAt: -1 });

  res.json(notifications);
});

module.exports = router;
