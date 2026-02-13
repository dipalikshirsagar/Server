const mongoose = require("mongoose");
const TaskWorkLog = require("../models/TaskWorkLog");

async function getDailyEmployeeWorkload(date) {
  const start = new Date(date);
  start.setHours(0, 0, 0, 0);

  const end = new Date(date);
  end.setHours(23, 59, 59, 999);

  return await TaskWorkLog.aggregate([
    // 1️⃣ Filter logs for the day
    {
      $match: {
        date: { $gte: start, $lte: end },
        status: { $ne: "Rejected" },
      },
    },

    // 2️⃣ Group per employee + task (daily logged hours per task)
    {
      $group: {
        _id: {
          employee: "$employee",
          task: "$task",
        },
        loggedHours: { $sum: "$totalHours" },
      },
    },

    // 3️⃣ Get task details
    {
      $lookup: {
        from: "tasks",
        localField: "_id.task",
        foreignField: "_id",
        as: "task",
      },
    },
    { $unwind: "$task" },

    // 4️⃣ Group per employee
    {
      $group: {
        _id: "$_id.employee",
        tasksCount: { $sum: 1 },
        totalLoggedHours: { $sum: "$loggedHours" },

        // 🔑 sum of daily estimated hours of tasks worked on that day
        totalDailyEstimatedHours: {
          $sum: "$task.dailyEstimatedHours",
        },
      },
    },

    // 5️⃣ Get employee details
    {
      $lookup: {
        from: "users",
        localField: "_id",
        foreignField: "_id",
        as: "employee",
      },
    },
    { $unwind: "$employee" },

    // 6️⃣ Calculate utilization
 {
  $project: {
    _id: 0,
    employeeId: "$employee._id",
    employeeName: "$employee.name",
    tasks: "$tasksCount",
    loggedHours: "$totalLoggedHours",
    estimatedHours: "$totalDailyEstimatedHours",

    utilization: {
      $multiply: [
        {
          $cond: [
            // ✅ Case 1: estimated hours exist → normal calculation
            { $gt: ["$totalDailyEstimatedHours", 0] },
            {
              $divide: [
                "$totalLoggedHours",
                "$totalDailyEstimatedHours"
              ]
            },

            // ⚠️ Case 2: estimated = 0
            {
              $cond: [
                // logged > 0 → overloaded
                { $gt: ["$totalLoggedHours", 0] },
                1, // 100%
                0  // logged = 0 → 0%
              ]
            }
          ]
        },
        100
      ]
    }
  }
},
    // 7️⃣ Status based on utilization
    {
      $addFields: {
        status: {
          $switch: {
            branches: [
              { case: { $lt: ["$utilization", 70] }, then: "Underloaded" },
              {
                case: {
                  $and: [
                    { $gte: ["$utilization", 70] },
                    { $lte: ["$utilization", 100] },
                  ],
                },
                then: "Balanced",
              },
              { case: { $gt: ["$utilization", 100] }, then: "Overloaded" },
            ],
            default: "Balanced",
          },
        },
      },
    },

    // 8️⃣ Sort A → Z
    {
      $sort: { employeeName: 1 },
    },
  ]);
}


async function getEmployeeWorkloadByWeekRange(startDate, endDate) {
  const result = await TaskWorkLog.aggregate([
    // 1️⃣ Filter logs in date range
    {
      $match: {
        date: { $gte: startDate, $lte: endDate },
        status: { $ne: "Rejected" },
      },
    },

    // 2️⃣ Group by employee + task + day
    {
      $group: {
        _id: {
          employee: "$employee",
          task: "$task",
          day: {
            $dateToString: { format: "%Y-%m-%d", date: "$date" },
          },
        },
        loggedHours: { $sum: "$totalHours" },
      },
    },

    // 3️⃣ Lookup task details
    {
      $lookup: {
        from: "tasks",
        localField: "_id.task",
        foreignField: "_id",
        as: "task",
      },
    },
    { $unwind: "$task" },

    // 4️⃣ Group per employee
    {
      $group: {
        _id: "$_id.employee",

        tasksCount: { $sum: 1 },
        totalLoggedHours: { $sum: "$loggedHours" },

        // 🔑 Sum DAILY estimated hours for each task-day
        totalDailyEstimatedHours: {
          $sum: "$task.dailyEstimatedHours",
        },

        workedDays: { $addToSet: "$_id.day" },
      },
    },

    // 5️⃣ Count worked days
    {
      $addFields: {
        workedDaysCount: { $size: "$workedDays" },
      },
    },

    // 6️⃣ Lookup employee details
    {
      $lookup: {
        from: "users",
        localField: "_id",
        foreignField: "_id",
        as: "employee",
      },
    },
    { $unwind: "$employee" },

    // 7️⃣ Calculate utilization
  // 7️⃣ Calculate utilization (FIXED)
{
  $project: {
    _id: 0,
    employeeId: "$employee._id",
    employeeName: "$employee.name",
    tasks: "$tasksCount",
    workedDays: "$workedDaysCount",
    loggedHours: "$totalLoggedHours",
    estimatedHours: "$totalDailyEstimatedHours",

    utilization: {
      $multiply: [
        {
          $cond: [
            // ✅ If estimated hours exist → normal calculation
            { $gt: ["$totalDailyEstimatedHours", 0] },
            {
              $divide: [
                "$totalLoggedHours",
                "$totalDailyEstimatedHours"
              ]
            },

            // ⚠️ If estimated = 0 but logged > 0 → force overload
            {
              $cond: [
                { $gt: ["$totalLoggedHours", 0] },
                1,   // 100%
                0    // 0%
              ]
            }
          ]
        },
        100
      ]
    }
  }
},


    // 8️⃣ Status
    {
      $addFields: {
        status: {
          $switch: {
            branches: [
              { case: { $lt: ["$utilization", 70] }, then: "Underloaded" },
              {
                case: {
                  $and: [
                    { $gte: ["$utilization", 70] },
                    { $lte: ["$utilization", 100] },
                  ],
                },
                then: "Balanced",
              },
              { case: { $gt: ["$utilization", 100] }, then: "Overloaded" },
            ],
            default: "Balanced",
          },
        },
      },
    },

    // 9️⃣ Sort
    {
      $sort: { employeeName: 1 },
    },
  ]);

  return result;
}

async function getEmployeeWorkloadByRange(startDate, endDate) {
  const result = await TaskWorkLog.aggregate([
    // 1️⃣ Filter logs in date range
    {
      $match: {
        date: { $gte: startDate, $lte: endDate },
        status: { $ne: "Rejected" },
      },
    },

    // 2️⃣ Group by employee + task + day
    {
      $group: {
        _id: {
          employee: "$employee",
          task: "$task",
          day: {
            $dateToString: { format: "%Y-%m-%d", date: "$date" },
          },
        },
        loggedHours: { $sum: "$totalHours" },
      },
    },

    // 3️⃣ Lookup task details
    {
      $lookup: {
        from: "tasks",
        localField: "_id.task",
        foreignField: "_id",
        as: "task",
      },
    },
    { $unwind: "$task" },

    // 4️⃣ Group per employee
    {
      $group: {
        _id: "$_id.employee",

        tasksCount: { $sum: 1 },
        totalLoggedHours: { $sum: "$loggedHours" },

        // 🔑 Sum DAILY estimated hours per logged task-day
        totalDailyEstimatedHours: {
          $sum: "$task.dailyEstimatedHours",
        },

        workedDays: { $addToSet: "$_id.day" },
      },
    },

    // 5️⃣ Count worked days
    {
      $addFields: {
        workedDaysCount: { $size: "$workedDays" },
      },
    },

    // 6️⃣ Lookup employee details
    {
      $lookup: {
        from: "users",
        localField: "_id",
        foreignField: "_id",
        as: "employee",
      },
    },
    { $unwind: "$employee" },

    // 7️⃣ Calculate utilization
    // 7️⃣ Calculate utilization (FIXED)
{
  $project: {
    _id: 0,
    employeeId: "$employee._id",
    employeeName: "$employee.name",
    tasks: "$tasksCount",
    workedDays: "$workedDaysCount",
    loggedHours: "$totalLoggedHours",
    estimatedHours: "$totalDailyEstimatedHours",

    utilization: {
      $multiply: [
        {
          $cond: [
            // ✅ If estimated hours exist → normal calculation
            { $gt: ["$totalDailyEstimatedHours", 0] },
            {
              $divide: [
                "$totalLoggedHours",
                "$totalDailyEstimatedHours"
              ]
            },

            // ⚠️ If estimated = 0 but logged > 0 → force overload
            {
              $cond: [
                { $gt: ["$totalLoggedHours", 0] },
                1,   // 100%
                0    // 0%
              ]
            }
          ]
        },
        100
      ]
    }
  }
},


    // 8️⃣ Status
    {
      $addFields: {
        status: {
          $switch: {
            branches: [
              { case: { $lt: ["$utilization", 70] }, then: "Underloaded" },
              {
                case: {
                  $and: [
                    { $gte: ["$utilization", 70] },
                    { $lte: ["$utilization", 100] },
                  ],
                },
                then: "Balanced",
              },
              { case: { $gt: ["$utilization", 100] }, then: "Overloaded" },
            ],
            default: "Balanced",
          },
        },
      },
    },

    // 9️⃣ Sort
    {
      $sort: { employeeName: 1 },
    },
  ]);

  return result;
}




module.exports = {
  getEmployeeWorkloadByRange,
  getDailyEmployeeWorkload,
  getEmployeeWorkloadByWeekRange
};
