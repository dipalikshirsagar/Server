//whole code added by Rushikesh
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
          url: file.path, // cloudinary url
          public_id: file.filename, // cloudinary public id
        });
      }),
    );

    res.status(200).json(items);
  } catch (err) {
    console.error("UPLOAD ERROR:", err);
    res.status(500).json({ message: err.message || "Upload failed" });
  }
});

/* ================= GET ================= */
router.get("/", async (req, res) => {
  try {
    const items = await Gallery.find().sort({ createdAt: -1 });
    res.json(items);
  } catch (err) {
    console.error("FETCH ERROR:", err);
    res.status(500).json({ message: "Fetch failed" });
  }
});

router.put("/:id", upload.single("file"), async (req, res) => {
  try {
    const item = await Gallery.findById(req.params.id);
    if (!item) return res.status(404).json({ message: "Not found" });

    const updateData = {
      title: req.body?.title ?? item.title,
      description: req.body?.description ?? item.description,
      category: req.body?.category ?? item.category,
    };

    if (req.file) {
      // old cloudinary delete
      if (item.public_id) {
        await cloudinary.uploader.destroy(item.public_id, {
          resource_type: item.type === "pdf" ? "raw" : item.type,
        });
      }

      updateData.type = req.file.mimetype.startsWith("image")
        ? "image"
        : req.file.mimetype.startsWith("video")
          ? "video"
          : "pdf";

      updateData.url = req.file.path; // ✅ add this
      updateData.public_id = req.file.filename; // ✅ add this
    }

    const updated = await Gallery.findByIdAndUpdate(req.params.id, updateData, {
      new: true,
      runValidators: true,
    });

    res.json(updated);
  } catch (err) {
    console.error("UPDATE ERROR:", err);
    res.status(500).json({ message: err.message || "Update failed" });
  }
});

router.delete("/:id", async (req, res) => {
  try {
    const item = await Gallery.findById(req.params.id);

    if (!item) {
      return res.status(404).json({ message: "Item not found" });
    }

    let resourceType = "image";

    if (item.type === "video") {
      resourceType = "video";
    } else if (item.type === "pdf") {
      resourceType = "raw";
    }

    if (item.public_id) {
      await cloudinary.uploader.destroy(item.public_id, {
        resource_type: resourceType,
      });
    }

    await Gallery.findByIdAndDelete(req.params.id);

    res.json({ message: "Deleted successfully" });
  } catch (err) {
    console.error("DELETE ERROR:", err);
    res.status(500).json({ message: err.message || "Delete failed" });
  }
});
module.exports = router;
