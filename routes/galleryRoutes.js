// const express = require("express");
// const router = express.Router();
// const multer = require("multer");

// const { cloudinary, storage } = require("../cloudinary");
// const Gallery = require("../models/GallerySchema");

// const upload = multer({ storage });

// /* ================= UPLOAD ================= */
// router.post("/upload", upload.array("files"), async (req, res) => {
//   try {
//     const items = await Promise.all(
//       req.files.map((file, index) => {
//         const type = file.mimetype.startsWith("image")
//           ? "image"
//           : file.mimetype.startsWith("video")
//           ? "video"
//           : "pdf";

//         return Gallery.create({
//           title: req.body.titles[index],
//           description: req.body.descriptions[index],
//           type,
//           url: file.path,
//           public_id: file.filename,
//         });
//       })
//     );

//     res.status(200).json(items);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: "Upload failed" });
//   }
// });

// /* ================= GET ================= */
// router.get("/", async (req, res) => {
//   try {
//     const items = await Gallery.find().sort({ createdAt: -1 });
//     res.json(items);
//   } catch (err) {
//     res.status(500).json({ message: "Fetch failed" });
//   }
// });

// /* ================= UPDATE (EDIT) ================= */
// router.put("/:id", async (req, res) => {
//   try {
//     const { title, description } = req.body;

//     const updatedItem = await Gallery.findByIdAndUpdate(
//       req.params.id,
//       { title, description },
//       { new: true }
//     );

//     if (!updatedItem) {
//       return res.status(404).json({ message: "Not found" });
//     }

//     res.json(updatedItem);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: "Update failed" });
//   }
// });

// /* ================= DELETE ================= */
// router.delete("/:id", async (req, res) => {
//   try {
//     const item = await Gallery.findById(req.params.id);
//     if (!item) return res.status(404).json({ message: "Not found" });

//     await cloudinary.uploader.destroy(item.public_id, {
//       resource_type: item.type === "pdf" ? "raw" : item.type,
//     });

//     await item.deleteOne();
//     res.json({ message: "Deleted" });
//   } catch (err) {
//     res.status(500).json({ message: "Delete failed" });
//   }
// });

// module.exports = router;



const express = require("express");
const router = express.Router();
const multer = require("multer");
const { cloudinary, storage } = require("../cloudinary");
const Gallery = require("../models/GallerySchema");

const upload = multer({ storage });

/* ================= UPLOAD ================= */
router.post("/upload", upload.array("files"), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: "No files uploaded" });
    }

    const { titles = [], descriptions = [], categories = [] } = req.body;

    const items = await Promise.all(
      req.files.map((file, index) => {
        const type = file.mimetype.startsWith("image")
          ? "image"
          : file.mimetype.startsWith("video")
          ? "video"
          : "pdf";

        if (!categories[index]) {
          throw new Error(`Category missing for file ${index + 1}`);
        }

        return Gallery.create({
          title: titles[index] || "",
          description: descriptions[index] || "",
          category: categories[index],
          type,
          url: file.path,
          public_id: file.filename,
        });
      })
    );

    res.status(200).json(items);
  } catch (err) {
    console.error("UPLOAD ERROR:", err);
    res.status(500).json({ message: err.message });
  }
});

/* ================= GET ================= */
router.get("/", async (req, res) => {
  const items = await Gallery.find().sort({ createdAt: -1 });
  res.json(items);
});

/* ================= UPDATE ================= */
router.put("/:id", async (req, res) => {
  const updated = await Gallery.findByIdAndUpdate(
    req.params.id,
    req.body,
    { new: true }
  );
  res.json(updated);
});

/* ================= DELETE ================= */
router.delete("/:id", async (req, res) => {
  const item = await Gallery.findById(req.params.id);

  await cloudinary.uploader.destroy(item.public_id, {
    resource_type: item.type === "pdf" ? "raw" : item.type,
  });

  await item.deleteOne();
  res.json({ message: "Deleted" });
});

module.exports = router;