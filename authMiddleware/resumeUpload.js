

const { v2: cloudinary } = require("cloudinary");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const multer = require("multer");

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_KEY,
  api_secret: process.env.CLOUD_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => ({
    folder: "interview_resumes",
    resource_type: "raw", 
    public_id: `${Date.now()}-${file.originalname.replace(/\s/g, "_")}`,
    type: "upload",
  }),
});

const resumeUpload = multer({ storage });

module.exports = resumeUpload;



