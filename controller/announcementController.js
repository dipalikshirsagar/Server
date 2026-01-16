const Announcement = require("../models/AnnouncementSchema");
const User = require("../models/User");
const Notification = require("../models/notificationSchema");



exports.createAnnouncement = async (req, res) => {
  try {
    const { name, description, publishDate, expirationDate, category, isActive } = req.body;

    // Basic validation
    if (!name) return res.status(400).json({ message: "Name is required" });
    if (name.length > 50) return res.status(400).json({ message: "Name must be less than 50 characters" });

    if (!description) return res.status(400).json({ message: "Description is required" });
    if (description.length > 200) return res.status(400).json({ message: "Description must be less than 200 characters" });

    if (!publishDate) return res.status(400).json({ message: "Publish date is required" });
    if (!category) return res.status(400).json({ message: "Category is required" });

    if (expirationDate && new Date(expirationDate) < new Date(publishDate)) {
      return res.status(400).json({ message: "Expiration date must be after publish date" });
    }

    const newAnnouncement = await Announcement.create({
      name,
      description,
      publishDate,
      expirationDate: expirationDate || null,
      category,
      image: req.files?.image?.[0]?.path || null,
      isActive: isActive || false
    });

    const users = await User.find({}, "_id");

    // 3️⃣ Create notifications for all users
    const notifications = users.map((user) => ({
        user: user._id,
        type: "Announcements",
        message: `New announcement: ${newAnnouncement.name}`,
      }));

    if (notifications.length > 0) {
      await Notification.insertMany(notifications);
    }

    res.status(201).json({
      message: "Announcement created successfully",
      announcement: newAnnouncement
    });

  } catch (error) {
    console.error("CREATE ANNOUNCEMENT ERROR:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// GET all Announcements
exports.getAnnouncements = async (req, res) => {
  try {
    const announcements = await Announcement.find().sort({ publishDate: -1 });

    res.status(200).json({
      success: true,
      data: announcements
    });
  } catch (error) {
    console.error("GET ANNOUNCEMENTS ERROR:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error"
    });
  }
};


