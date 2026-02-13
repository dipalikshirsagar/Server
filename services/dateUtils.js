const mongoose = require("mongoose");




// utils/dateUtils.js
function getValidWorkingDays(startDate, endDate) {
  let count = 0;

  const start = new Date(startDate);
  const end = new Date(endDate);

  // Normalize to start/end of day (VERY IMPORTANT)
  start.setHours(0, 0, 0, 0);
  end.setHours(23, 59, 59, 999);

  const date = new Date(start);

  while (date <= end) {
    const day = date.getDay(); // 0 = Sunday, 6 = Saturday
    const weekOfMonth = Math.ceil(date.getDate() / 7);

    const isSunday = day === 0;
    const isFirstOrThirdSaturday =
      day === 6 && (weekOfMonth === 1 || weekOfMonth === 3);

    if (!isSunday && !isFirstOrThirdSaturday) {
      count++;
    }

    date.setDate(date.getDate() + 1);
  }

  return count;
}


module.exports = { getValidWorkingDays };
