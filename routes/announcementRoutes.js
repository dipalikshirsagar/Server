const express = require("express");
const router = express.Router();

const {
  createAnnouncement,
  getAnnouncements
 
} = require("../controller/announcementController");
const { v2: cloudinary } = require("cloudinary");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const dotenv = require("dotenv");
const multer = require("multer");

dotenv.config();

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_KEY,
  api_secret: process.env.CLOUD_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => ({
    folder: "announcements",
    resource_type: "image"
  })
});

const upload = multer({ storage });
router.get("/", getAnnouncements);
router.post("/", upload.fields([{ name: "image", maxCount: 1 }]), createAnnouncement);


module.exports = router;
