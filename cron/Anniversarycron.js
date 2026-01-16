const cron = require("node-cron");
const User = require("../models/User");
const { autoSendAnniversaryEmail } = require("../server");

// Run every day at 9:30 AM IST
cron.schedule("30 9 * * *", async () => {
  console.log(" Running Daily Anniversary Cron Job...");
  
  try {
    const today = new Date();
    
    // Get all employees with DOJ
    const employees = await User.find({ 
      doj: { $ne: null, $exists: true },
      isDeleted: false 
    });
    
    console.log(` Checking ${employees.length} employees for anniversaries...`);
    
    let anniversaryCount = 0;
    
    for (const emp of employees) {
      const doj = new Date(emp.doj);
      
      // Check if today is their anniversary
      if (doj.getDate() === today.getDate() && 
          doj.getMonth() === today.getMonth()) {
        
        const years = today.getFullYear() - doj.getFullYear();
        
        // Skip if 0 years (joining date is today)
        if (years === 0) continue;
        
        await autoSendAnniversaryEmail(emp);
        anniversaryCount++;
        console.log(`🎊 Anniversary processed for: ${emp.name} (${years} years)`);
      }
    }
    
    console.log(` Anniversary cron completed. Found ${anniversaryCount} anniversary(ies) today.`);
    
  } catch (err) {
    console.error(" Anniversary Cron error:", err.message);
  }
});

console.log(" Anniversary cron job scheduled for 9:30 AM daily");

module.exports = {};
