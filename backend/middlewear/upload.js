const multer = require("multer");
const multerS3 = require("multer-s3");
const s3 = require("../config/s3");

const upload = multer({
  storage: multerS3({
    s3,
    bucket: process.env.AWS_BUCKET_NAME,
    contentType: multerS3.AUTO_CONTENT_TYPE,

    key: (req, file, cb) => {
      try {
        const username = req.session.username || "anonymous";
        const subjectName = req.body.subjectName || "UnknownSubject";

        const now = new Date();
        const timestamp =
          now.getDate().toString().padStart(2, "0") +
          (now.getMonth() + 1).toString().padStart(2, "0") +
          now.getFullYear() +
          now.getHours().toString().padStart(2, "0") +
          now.getMinutes().toString().padStart(2, "0");

        const s3Path = `InterviewAns/${username}/${subjectName}/${timestamp}.mp4`;
        cb(null, s3Path);
      } catch (err) {
        cb(err);
      }
    }
  }),

  limits: { fileSize: 500 * 1024 * 1024 },

  fileFilter: (req, file, cb) => {
    const allowed = ["video/mp4", "video/webm", "video/quicktime"];
    allowed.includes(file.mimetype)
      ? cb(null, true)
      : cb(new Error("Only video files allowed"));
  }
});

module.exports = upload;
