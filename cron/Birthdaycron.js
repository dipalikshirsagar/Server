// const cron = require("node-cron");
// const User = require("../models/User");
// const { autoSendBirthdayEmail } = require("../server");

// cron.schedule("0 9 * * *", async () => {  // 9 AM daily
//   console.log(" Running Daily Birthday Cron Job...");
//   try {
//     const employees = await User.find({ dob: { $ne: null } });// matches dob of employee
//     let birthdayCount = 0;
//     for (const emp of employees) {
//       await autoSendBirthdayEmail(emp); //auto send email
//       birthdayCount++;
//     }
//     console.log(` Checked ${birthdayCount} employees for birthdays`);
//   } catch (err) {
//     console.error("Birthday Cron error:", err);
//   }
// });

// module.exports = {};

const cron = require("node-cron");
const User = require("../models/User");
const { autoSendBirthdayEmail } = require("../server");

// Run every day at 9 AM IST
cron.schedule("0 9 * * *", async () => {
  console.log(" Running Daily Birthday Cron Job...");
  
  try {
    const today = new Date();
    
    // Get all employees with DOB
    const employees = await User.find({ 
      dob: { $ne: null, $exists: true },
      isDeleted: false 
    });
    
    console.log(` Checking ${employees.length} employees for birthdays...`);
    
    let birthdayCount = 0;
    
    for (const emp of employees) {
      const dob = new Date(emp.dob);
      
      // Check if today is their birthday
      if (dob.getDate() === today.getDate() && 
          dob.getMonth() === today.getMonth()) {
        
        await autoSendBirthdayEmail(emp);
        birthdayCount++;
        console.log(` Birthday processed for: ${emp.name}`);
      }
    }
    
    console.log(` Birthday cron completed. Found ${birthdayCount} birthday(s) today.`);
    
  } catch (err) {
    console.error(" Birthday Cron error:", err.message);
  }
});

console.log(" Birthday cron job scheduled for 9:00 AM daily");

module.exports = {};
