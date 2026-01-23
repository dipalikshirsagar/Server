const mongoose = require("mongoose");
const TaskWorkLog = require("../models/TaskWorkLog");

//get Employee workload daily
// async function getDailyEmployeeWorkload(date) {
//   const start = new Date(date);
//   start.setHours(0, 0, 0, 0);

//   const end = new Date(date);
//   end.setHours(23, 59, 59, 999);

//   return await TaskWorkLog.aggregate([
//     {
//       $match: {
//         date: { $gte: start, $lte: end },
//         status: { $ne: "Rejected" }
//       }
//     },
//     {
//       $group: {
//         _id: {
//           employee: "$employee",
//           task: "$task"
//         },
//         loggedHours: { $sum: "$totalHours" }
//       }
//     },
//     {
//       $lookup: {
//         from: "tasks",
//         localField: "_id.task",
//         foreignField: "_id",
//         as: "task"
//       }
//     },
//     { $unwind: "$task" },
//     {
//       $group: {
//         _id: "$_id.employee",
//         tasksCount: { $sum: 1 },
//         totalEstimatedHours: { $sum: "$task.estimatedHours" },
//         totalLoggedHours: { $sum: "$loggedHours" }
//       }
//     },
//     {
//       $lookup: {
//         from: "users",
//         localField: "_id",
//         foreignField: "_id",
//         as: "employee"
//       }
//     },
//     { $unwind: "$employee" },
//     {
//       $project: {
//         _id: 0,
//         employeeId: "$employee._id",
//         employeeName: "$employee.name",
//         tasks: "$tasksCount",
//         estimatedHours: "$totalEstimatedHours",
//         loggedHours: "$totalLoggedHours",
//         utilization: {
//           $multiply: [
//             { $divide: ["$totalLoggedHours", 8] },
//             100
//           ]
//         },
//         status: {
//           $cond: [
//             { $gt: ["$totalLoggedHours", 8] },
//             "Overloaded",
//             "Balanced"
//           ]
//         }
//       }
//     }
//   ]);
// }
async function getDailyEmployeeWorkload(date) {
  const start = new Date(date);
  start.setHours(0, 0, 0, 0);

  const end = new Date(date);
  end.setHours(23, 59, 59, 999);

  return await TaskWorkLog.aggregate([
    {
      $match: {
        date: { $gte: start, $lte: end },
        status: { $ne: "Rejected" },
      },
    },
    {
      $group: {
        _id: {
          employee: "$employee",
          task: "$task",
        },
        loggedHours: { $sum: "$totalHours" },
      },
    },
    {
      $lookup: {
        from: "tasks",
        localField: "_id.task",
        foreignField: "_id",
        as: "task",
      },
    },
    { $unwind: "$task" },
    {
      $group: {
        _id: "$_id.employee",
        tasksCount: { $sum: 1 },
        totalEstimatedHours: { $sum: "$task.estimatedHours" },
        totalLoggedHours: { $sum: "$loggedHours" },
      },
    },
    {
      $lookup: {
        from: "users",
        localField: "_id",
        foreignField: "_id",
        as: "employee",
      },
    },
    { $unwind: "$employee" },

    {
      $addFields: {
        dailyCapacity: 9,
      },
    },

    {
      $project: {
        _id: 0,
        employeeId: "$employee._id",
        employeeName: "$employee.name",
        tasks: "$tasksCount",
        estimatedHours: "$totalEstimatedHours",
        loggedHours: "$totalLoggedHours",
        capacity: "$dailyCapacity",

        utilization: {
          $multiply: [
            { $divide: ["$totalLoggedHours", "$dailyCapacity"] },
            100,
          ],
        },

        status: {
          $switch: {
            branches: [
              {
                case: { $gt: ["$totalLoggedHours", "$dailyCapacity"] },
                then: "Overloaded",
              },
              {
                case: {
                  $lt: [
                    {
                      $divide: ["$totalLoggedHours", "$dailyCapacity"],
                    },
                    0.5,
                  ],
                },
                then: "Underloaded",
              },
            ],
            default: "Balanced",
          },
        },
      },
    },
  ]);
}

//get Employee workload by range

// async function getEmployeeWorkloadByRange(startDate, endDate, capacityPerDay = 9) {
//   return await TaskWorkLog.aggregate([
//     {
//       $match: {
//         date: { $gte: startDate, $lte: endDate },
//         status: { $ne: "Rejected" }
//       }
//     },
//     {
//       $group: {
//         _id: {
//           employee: "$employee",
//           task: "$task"
//         },
//         loggedHours: { $sum: "$totalHours" }
//       }
//     },
//     {
//       $lookup: {
//         from: "tasks",
//         localField: "_id.task",
//         foreignField: "_id",
//         as: "task"
//       }
//     },
//     { $unwind: "$task" },
//     {
//       $group: {
//         _id: "$_id.employee",
//         tasksCount: { $sum: 1 },
//         totalEstimatedHours: { $sum: "$task.estimatedHours" },
//         totalLoggedHours: { $sum: "$loggedHours" }
//       }
//     },
//     {
//       $lookup: {
//         from: "users",
//         localField: "_id",
//         foreignField: "_id",
//         as: "employee"
//       }
//     },
//     { $unwind: "$employee" },

//     // Step 1: calculate utilization
//     {
//       $project: {
//         _id: 0,
//         employeeId: "$employee._id",
//         employeeName: "$employee.name",
//         tasks: "$tasksCount",
//         estimatedHours: "$totalEstimatedHours",
//         loggedHours: "$totalLoggedHours",
//         utilization: {
//           $multiply: [
//             { $divide: ["$totalLoggedHours", capacityPerDay] },
//             100
//           ]
//         }
//       }
//     },

//     // Step 2: assign status
//     {
//       $addFields: {
//         status: {
//           $switch: {
//             branches: [
//               {
//                 case: { $lt: ["$utilization", 70] },
//                 then: "Underbalanced"
//               },
//               {
//                 case: {
//                   $and: [
//                     { $gte: ["$utilization", 70] },
//                     { $lte: ["$utilization", 100] }
//                   ]
//                 },
//                 then: "Balanced"
//               },
//               {
//                 case: { $gt: ["$utilization", 100] },
//                 then: "Overloaded"
//               }
//             ],
//             default: "Balanced"
//           }
//         }
//       }
//     }
//   ]);
// }
async function getEmployeeWorkloadByRange(
  startDate,
  endDate,
  weeklyCapacity = 9 * 5
) {
  return await TaskWorkLog.aggregate([
    // Step 1: Filter logs by date and exclude rejected tasks
    {
      $match: {
        date: { $gte: startDate, $lte: endDate },
        status: { $ne: "Rejected" },
      },
    },

    // Step 2: Group by employee + task + day to calculate daily logged hours per task
    {
      $group: {
        _id: {
          employee: "$employee",
          task: "$task",
          day: { $dateToString: { format: "%Y-%m-%d", date: "$date" } }, // distinct day
        },
        loggedHours: { $sum: "$totalHours" },
      },
    },

    // Step 3: Lookup task details
    {
      $lookup: {
        from: "tasks",
        localField: "_id.task",
        foreignField: "_id",
        as: "task",
      },
    },
    { $unwind: "$task" },

    // Step 4: Group by employee to aggregate tasks, total hours, and distinct days
    {
      $group: {
        _id: "$_id.employee",
        tasksCount: { $sum: 1 },
        totalEstimatedHours: { $sum: "$task.estimatedHours" },
        totalLoggedHours: { $sum: "$loggedHours" },
        distinctDays: { $addToSet: "$_id.day" }, // set of logged days
      },
    },

    // Step 5: Count number of days employee actually logged work
    {
      $addFields: {
        loggedDaysCount: { $size: "$distinctDays" },
      },
    },

    // Step 6: Lookup employee details
    {
      $lookup: {
        from: "users",
        localField: "_id",
        foreignField: "_id",
        as: "employee",
      },
    },
    { $unwind: "$employee" },

    // Step 7: Calculate utilization per actual logged day
    {
      $project: {
        _id: 0,
        employeeId: "$employee._id",
        employeeName: "$employee.name",
        tasks: "$tasksCount",
        estimatedHours: "$totalEstimatedHours",
        loggedHours: "$totalLoggedHours",
        utilization: {
          $multiply: [
            {
              $divide: [
                "$totalLoggedHours",
                { $multiply: ["$loggedDaysCount", weeklyCapacity / 5] }, // daily capacity * actual days
              ],
            },
            100,
          ],
        },
      },
    },

    // Step 8: Assign status based on utilization
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
  ]);
}

module.exports = {
  getEmployeeWorkloadByRange,
  getDailyEmployeeWorkload,
};
