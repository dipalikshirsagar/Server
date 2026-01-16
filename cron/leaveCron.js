const cron = require("node-cron");
const User = require("../models/userModel");
const transporter = require("../config/mail");

// Yearly leaves
const YEARLY_CL = 8;
const YEARLY_SL = 6;

// Daily Cron – runs every midnight
cron.schedule("0 0 * * *", async () => {
  console.log("🔄 Running Daily Leave Cron Job...");

  try {
    const today = new Date();

    // Find employees whose probation is now completed
    const employees = await User.find({
      probationCompleted: false,
      doj: { $ne: null }
    });

    let creditedCount = 0;

    for (const emp of employees) {
      const probationEnd = new Date(emp.doj);
      probationEnd.setMonth(probationEnd.getMonth() + emp.probationMonths);

      if (today >= probationEnd) {
        console.log(`🎉 Probation completed for: ${emp.name}`);

        emp.casualLeaveBalance += YEARLY_CL;
        emp.sickLeaveBalance += YEARLY_SL;
        emp.probationCompleted = true;
        emp.lastLeaveUpdate = today;

        await emp.save();
        creditedCount++;

        // Notify employee via Email
        try {
          await transporter.sendMail({
            from: `"CWS EMS" <${process.env.EMAIL_USER}>`,
            to: emp.email,
            subject: "Leave Balance Credited",
            text: `Congratulations! Your probation is completed and yearly leaves have been credited.`
          });
        } catch (err) {
          console.error("Email error:", err.message);
        }
      }
    }

    console.log(`✅ Total Employees credited: ${creditedCount}`);

  } catch (err) {
    console.error("Cron job error:", err);
  }
});

module.exports = {};
