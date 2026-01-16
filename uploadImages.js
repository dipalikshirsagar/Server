import { v2 as cloudinary } from "cloudinary";
import dotenv from "dotenv";
dotenv.config();


cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_KEY,
  api_secret: process.env.CLOUD_SECRET,
});

const images = [
  "./uploads/image2.png",
  "./uploads/instagram.png",
  "./uploads/linkedin.png",
  "./uploads/logo.jpeg",
  "./uploads/pass.jpg",
  "./uploads/passwordreest.png"
];

async function uploadAll() {
  for (let img of images) {
    const result = await cloudinary.uploader.upload(img, {
      folder: "email-assets",
    });
    console.log(img, "=>", result.secure_url);
  }
}

uploadAll();
