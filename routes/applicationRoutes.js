const router = require("express").Router();
const controller = require("../controller/applicationController");
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


    return {
      folder: "uploads",
      resource_type: "raw",
      format: "pdf"

    };
  },
});

const upload = multer({ storage });
router.post("/", upload.fields([{ name: "resumeUrl", maxCount: 1 }]), controller.createApplication);
router.get("/", controller.getApplications);
router.get("/job/:jobId", controller.getApplicationsByJob);
router.get("/employee/:employeeId", controller.getApplicationsByEmployee);
router.get("/resume/:publicId", controller.getResume);
router.get("/:id", controller.getApplicationById);
router.put("/:id", upload.fields([{ name: "resumeUrl", maxCount: 1 }]), controller.updateApplication);
router.delete("/:id", controller.deleteApplication);


module.exports = router;
