// cloudinary.js
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_KEY,
  api_secret: process.env.CLOUD_SECRET,
});

const galleryStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "gallery",
    resource_type: "auto",
  },
});
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "uploads",
    resource_type: "auto",
  },
});

export { cloudinary, storage };
