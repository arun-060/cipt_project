const express = require("express");
const upload = require("../middleware/upload");
const router = express.Router();

router.post("/upload-answer", upload.single("video"), (req, res) => {
  try {
    if (!req.session.loggedIn) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!req.file) {
      return res.status(400).json({ error: "No video uploaded" });
    }

    res.status(200).json({
      success: true,
      message: "Video uploaded to AWS S3",
      s3Key: req.file.key,
      s3Url: req.file.location
    });

  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
