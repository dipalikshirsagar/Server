import cron from "node-cron";
import Announcement from "../models/AnnouncementSchema";

cron.schedule("0 * * * *", async () => {
  // runs every hour
  const now = new Date();

  // Activate valid announcements
  await Announcement.updateMany(
    {
      publishDate: { $lte: now },
      $or: [
        { expirationDate: { $gte: now } },
        { expirationDate: null }
      ]
    },
    { isActive: true }
  );

  // Deactivate expired announcements
  await Announcement.updateMany(
    {
      expirationDate: { $lt: now }
    },
    { isActive: false }
  );

  console.log("Announcement isActive recalculated");
});
