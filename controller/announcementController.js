const Announcement = require("../models/AnnouncementSchema");
const User = require("../models/User");
const Notification = require("../models/notificationSchema");

exports.createAnnouncement = async (req, res) => {
  try {
    const {
      name,
      description,
      publishDate,
      expirationDate,
      category,
      isActive,
    } = req.body;

    // Basic validation
    if (!name) return res.status(400).json({ message: "Name is required" });
    if (name.length > 50)
      return res
        .status(400)
        .json({ message: "Name must be less than 50 characters" });

    if (!description)
      return res.status(400).json({ message: "Description is required" });
    if (description.length > 200)
      return res
        .status(400)
        .json({ message: "Description must be less than 200 characters" });

    if (!publishDate)
      return res.status(400).json({ message: "Publish date is required" });
    if (!category)
      return res.status(400).json({ message: "Category is required" });

    if (expirationDate && new Date(expirationDate) < new Date(publishDate)) {
      return res
        .status(400)
        .json({ message: "Expiration date must be after publish date" });
    }

    const newAnnouncement = await Announcement.create({
      name,
      description,
      publishDate,
      expirationDate: expirationDate || null,
      category,
      image: req.files?.image?.[0]?.path || null,
      isActive: isActive || false,
    });

    const users = await User.find({ role: { $ne: "admin" } }, "_id");

    // 3️⃣ Create notifications for all users
    //added by shivani
    const notifications = users.map((user) => ({
      user: user._id,
      type: "Announcements",
      message: `New announcement: ${newAnnouncement.name}`,
      triggeredByRole: "HR", 
      announcementRef: newAnnouncement._id,
      isRead: false,
      createdAt: new Date(),
    }));

    if (notifications.length > 0) {
      await Notification.insertMany(notifications);
    }

    res.status(201).json({
      message: "Announcement created successfully",
      announcement: newAnnouncement,
    });
  } catch (error) {
    console.error("CREATE ANNOUNCEMENT ERROR:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// GET all Announcements
exports.getAnnouncements = async (req, res) => {
  try {
    const announcements = await Announcement.find().sort({ createdAt: -1});

    res.status(200).json({
      success: true,
      data: announcements,
    });
  } catch (error) {
    console.error("GET ANNOUNCEMENTS ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};

// DELETE Announcement added by samiksha
exports.deleteAnnouncement = async (req, res) => {
  try {
    const { id } = req.params;

    const deletedAnnouncement = await Announcement.findByIdAndDelete(id);

    if (!deletedAnnouncement) {
      return res.status(404).json({
        success: false,
        message: "Announcement not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Announcement deleted successfully",
    });
  } catch (error) {
    console.error("DELETE ANNOUNCEMENT ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};

//snehal code
exports.updateAnnouncement = async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      description,
      category,
      publishDate,
      expirationDate,
      isActive,
    } = req.body;

    const announcement = await Announcement.findById(id);
    if (!announcement) {
      return res.status(404).json({ message: "Announcement not found" });
    }

    // ✅ Validations (same rules as create)
    if (name && name.length > 50)
      return res
        .status(400)
        .json({ message: "Name must be less than 50 characters" });

    if (description && description.length > 200)
      return res
        .status(400)
        .json({ message: "Description must be less than 200 characters" });

    if (
      expirationDate &&
      publishDate &&
      new Date(expirationDate) < new Date(publishDate)
    ) {
      return res
        .status(400)
        .json({ message: "Expiration date must be after publish date" });
    }

    // ✅ Update fields only if provided
    if (name) announcement.name = name;
    if (description) announcement.description = description;
    if (category) announcement.category = category;
    if (publishDate) announcement.publishDate = publishDate;
    if (expirationDate) announcement.expirationDate = expirationDate;
    if (typeof isActive !== "undefined") announcement.isActive = isActive;

    // ✅ If new image uploaded, replace old one
    if (req.files?.image?.[0]?.path) {
      announcement.image = req.files.image[0].path;
    }

    await announcement.save();

    res.status(200).json({
      success: true,
      message: "Announcement updated successfully",
      data: announcement,
    });
  } catch (error) {
    console.error("UPDATE ANNOUNCEMENT ERROR:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
