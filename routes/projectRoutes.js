// const express = require("express");
// const router = express.Router();
// const {
//   createProject,
//   getProjects,
//   getProjectById,
//   updateProject,
//   deleteProject,
//   getUniqueProjectNames,
//   getProjectsByManager,
//     updateProjectStatusByManager,

// } = require("../controller/projectController");
// const { v2: cloudinary } = require("cloudinary");
// const { CloudinaryStorage } = require("multer-storage-cloudinary");
// const dotenv = require("dotenv");
// const multer = require("multer");
// dotenv.config();

// cloudinary.config({
//   cloud_name: process.env.CLOUD_NAME,
//   api_key: process.env.CLOUD_KEY,
//   api_secret: process.env.CLOUD_SECRET,
// });

// const storage = new CloudinaryStorage({
//   cloudinary,
//   params: async (req, file) => {
//     let resourceType = "image";
//     if (file.mimetype === "application/pdf") resourceType = "raw";

//     return {
//       folder: "uploads",
//       resource_type: resourceType,
//     };
//   },
// });

// const upload = multer({ storage });
// router.get(
//   "/manager/:managerId",
//   getProjectsByManager
// );
// router.post(
//   "/",
//   upload.fields([{ name: "attachments", maxCount: 10 }]),
//   createProject
// );
// router.get("/unique-names/:managerId", getUniqueProjectNames);
// router.get("/", getProjects);
// router.get("/:id", getProjectById);
// router.put(
//   "/:id",
//   upload.fields([{ name: "attachments", maxCount: 10 }]),
//  updateProject
// );

// router.delete("/:id", deleteProject);
// router.put("/:id/status", updateProjectStatusByManager);
// module.exports = router;

//Komal

const express = require("express");
const router = express.Router();
const {
  createProject,
  getProjects,
  getProjectById,
  updateProject,
  deleteProject,
  getUniqueProjectNames,
  getProjectsByManager,
  updateProjectStatusByManager,
  completeProject,
  cancelProject,
  updateManualStatus,
} = require("../controller/projectController");
const { v2: cloudinary } = require("cloudinary");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const dotenv = require("dotenv");
const multer = require("multer");
dotenv.config();

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_KEY,
  api_secret: process.env.CLOUD_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    let resourceType = "image";
    if (file.mimetype === "application/pdf") resourceType = "raw";

    return {
      folder: "uploads",
      resource_type: resourceType,
    };
  },
});

const upload = multer({ storage });
router.get("/manager/:managerId", getProjectsByManager);
router.post(
  "/",
  upload.fields([{ name: "attachments", maxCount: 10 }]),
  createProject,
);
router.get("/unique-names/:managerId", getUniqueProjectNames);
router.get("/", getProjects);
router.get("/:id", getProjectById);
router.put(
  "/:id",
  upload.fields([{ name: "attachments", maxCount: 10 }]),
  updateProject,
);

router.delete("/:id", deleteProject);
router.put("/:id/status", updateProjectStatusByManager);
router.put("/:id/complete", completeProject);
router.put("/:id/cancel", cancelProject);

// admin can update status manually
router.put("/:id/manual-status", updateManualStatus);

module.exports = router;
