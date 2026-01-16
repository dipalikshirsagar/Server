const TaskType = require("../models/TaskTypeSchema");


exports.createTaskType = async (req, res) => {
  try {
    const taskType = await TaskType.create(req.body);
    res.status(201).json({
      message: "Task Type created successfully",
      taskType,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};


exports.getTaskTypes = async (req, res) => {
  try {
    const taskTypes = await TaskType.find();
    res.status(200).json(taskTypes);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


exports.getTaskTypeById = async (req, res) => {
  try {
    const taskType = await TaskType.findById(req.params.id);

    if (!taskType) {
      return res.status(404).json({ message: "Task Type not found" });
    }

    res.status(200).json(taskType);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


exports.updateTaskType = async (req, res) => {
  try {
    const updatedTaskType = await TaskType.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: true,
      }
    );

    if (!updatedTaskType) {
      return res.status(404).json({ message: "Task Type not found" });
    }

    res.json({
      message: "Task Type updated successfully",
      taskType: updatedTaskType,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};


exports.deleteTaskType = async (req, res) => {
  try {
    const taskType = await TaskType.findByIdAndDelete(req.params.id);

    if (!taskType) {
      return res.status(404).json({ message: "Task Type not found" });
    }

    res.json({ message: "Task Type deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.getUniqueTaskTypeNames = async (req, res) => {
  try {
    const names = await TaskType.distinct("name");

    return res.status(200).json({
      success: true,
      taskTypes: names,
    });
  } catch (error) {
    console.error("Error fetching unique task types:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};
