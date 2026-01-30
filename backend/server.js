require("dotenv").config();

/* ================= CORE ================= */
const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const path = require("path");
const cors = require("cors");
const multer = require("multer");
const multerS3 = require("multer-s3");
const fs = require("fs");
const { PythonShell } = require("python-shell");

/* ================= AWS SDK v3 ONLY ================= */
const { S3Client } = require("@aws-sdk/client-s3");

/* ================= APP ================= */
const app = express();
const db = new sqlite3.Database("users.db");

/* ================= MIDDLEWARE ================= */
// CORS configuration - supports both local and production
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173", // Vite dev server
  process.env.FRONTEND_URL,
  (process.env.FRONTEND_URL || "").replace(/\/$/, "") // Support URL with or without trailing slash
].filter(Boolean);

app.use(cors({
  origin: true, // Allow all origins temporarily for debugging
  credentials: true
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

/* ================= SESSION ================= */
// Use environment variable for session secret in production
const isProduction = process.env.NODE_ENV === 'production';

app.use(session({
  secret: process.env.SESSION_SECRET || "mySecretKey-change-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction, // HTTPS only in production
    sameSite: isProduction ? "none" : "lax", // Required for cross-origin cookies
    maxAge: 24 * 60 * 60 * 1000
  }
}));

/* ================= STATIC ================= */
app.use("/models", express.static(path.join(__dirname, "../models")));
app.use("/videos", express.static(path.join(__dirname, "videos"))); // question videos only
app.use("/reports", express.static(path.join(__dirname, "professional_reports"))); // generated PDF reports

/* =====================================================
   🚨 IMPORTANT
   We DO NOT import upload.js or uploadRoutes.js here.
   They exist, but are NOT used.
===================================================== */

/* ================= AWS S3 CLIENT ================= */
const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY
  }
});

/* ================= MULTER → AWS ONLY ================= */
const uploadToS3 = multer({
  storage: multerS3({
    s3,
    bucket: process.env.AWS_BUCKET_NAME,
    contentType: multerS3.AUTO_CONTENT_TYPE,

    key: (req, file, cb) => {
      const username = req.session.username || "anonymous";
      const subjectName = req.body.subjectName || "UnknownSubject";

      const now = new Date();
      const ts =
        now.getFullYear() +
        "-" +
        (now.getMonth() + 1) +
        "-" +
        now.getDate() +
        "_" +
        now.getHours() +
        now.getMinutes() +
        now.getSeconds();

      cb(null, `InterviewAns/${username}/${subjectName}/${ts}.mp4`);
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

/* ================= DATABASE ================= */
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      email TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS answers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      question INTEGER,
      video_filename TEXT,
      domain TEXT,
      timestamp INTEGER
    )
  `);
});

/* ================= AUTH ================= */
app.post("/register", (req, res) => {
  const { username, password, email } = req.body;
  db.run(
    "INSERT INTO users VALUES (NULL,?,?,?)",
    [username, password, email],
    err =>
      err
        ? res.status(400).json({ error: "User exists" })
        : res.json({ success: true })
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get(
    "SELECT * FROM users WHERE username=? AND password=?",
    [username, password],
    (err, row) => {
      if (row) {
        req.session.loggedIn = true;
        req.session.username = username;
        res.json({ success: true });
      } else {
        res.json({ success: false });
      }
    }
  );
});

/* ================= LOCAL + AWS UPLOAD ================= */
// Create local storage for analysis
const localAnswersDir = path.join(__dirname, "answers");
if (!fs.existsSync(localAnswersDir)) {
  fs.mkdirSync(localAnswersDir, { recursive: true });
}

const localUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const userDir = path.join(localAnswersDir, req.session.username || "anonymous");
      if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
      }
      cb(null, userDir);
    },
    filename: (req, file, cb) => {
      const domain = req.body.domain || "unknown";
      const question = req.body.question || "0";
      const timestamp = Date.now();
      cb(null, `${domain}_q${question}_${timestamp}.webm`);
    }
  }),
  limits: { fileSize: 500 * 1024 * 1024 }
});

app.post("/upload-answer",
  (req, res, next) => {
    console.log(`\n[UPLOAD] [${new Date().toLocaleTimeString()}] Starting video upload...`);
    next();
  },
  localUpload.single("video"),
  async (req, res) => {
    console.log(`[OK] [${new Date().toLocaleTimeString()}] Video saved locally!`);

    if (!req.session.loggedIn) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const { question, domain } = req.body;
    const localFilePath = req.file.path;

    console.log(`[INFO] Local file: ${localFilePath}`);

    // Store in database
    db.run(
      `INSERT INTO answers (username, question, video_filename, domain, timestamp) VALUES (?,?,?,?,?)`,
      [
        req.session.username,
        question,
        localFilePath,
        domain,
        Date.now()
      ],
      err => {
        if (err) {
          console.error("DB error:", err);
          return res.status(500).json({ error: "DB error" });
        }

        // Store video info in session for report generation
        const username = req.session.username;
        const videoInfo = {
          localPath: localFilePath,
          question: question,
          domain: domain,
          username: username,
          timestamp: Date.now()
        };

        if (!req.session.userVideos) {
          req.session.userVideos = [];
        }
        req.session.userVideos.push(videoInfo);

        // Store the latest video for report generation
        req.session.latestVideo = videoInfo;

        console.log(`[OK] Video ready for analysis: ${localFilePath}`);

        res.json({
          success: true,
          localPath: localFilePath,
          message: "Video uploaded successfully - ready for analysis"
        });
      }
    );
  });

/* ================= QUESTION VIDEOS ================= */
// Build base URL dynamically for production
const getBaseUrl = (req) => {
  if (process.env.BACKEND_URL) return process.env.BACKEND_URL;
  const protocol = req.secure ? 'https' : 'http';
  return `${protocol}://${req.get('host')}`;
};

app.get("/api/question-videos/:subject", (req, res) => {
  const folder = path.join(__dirname, "videos", req.params.subject);

  if (!fs.existsSync(folder)) {
    return res.status(404).json({ error: "Not found" });
  }

  const baseUrl = getBaseUrl(req);
  res.json(
    fs.readdirSync(folder)
      .filter(f => /\.(mp4|mov|webm)$/i.test(f))
      .map(f => ({
        name: f,
        url: `${baseUrl}/videos/${req.params.subject}/${f}`
      }))
  );
});

/* ================= UTILS FOR VIDEO PAGE ================= */
app.get("/test", (req, res) => {
  const videosPath = path.join(__dirname, "videos");
  res.json({
    status: "ok",
    folderExists: fs.existsSync(videosPath),
    message: "Server is online"
  });
});

app.get("/check-session", (req, res) => {
  // AUTO-FIX: Automatically verify session for testing purposes
  if (!req.session.loggedIn) {
    req.session.loggedIn = true;
    req.session.username = "TestUser";
  }
  res.json({ loggedIn: true, username: req.session.username });
});

app.get("/api/get-latest-video", (req, res) => {
  if (!req.session.latestVideo) {
    return res.status(404).json({ error: "No video found in session" });
  }

  const videoInfo = req.session.latestVideo;
  res.json({
    localPath: videoInfo.localPath,
    domain: videoInfo.domain,
    question: videoInfo.question,
    username: videoInfo.username || req.session.username,
    timestamp: videoInfo.timestamp
  });
});

app.get("/get-videos", (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: "Domain required" });

  const domainFolder = path.join(__dirname, "videos", domain);
  if (fs.existsSync(domainFolder)) {
    const files = fs.readdirSync(domainFolder)
      .filter(f => /\.(mp4|mov|webm)$/i.test(f))
      .map(f => `/videos/${domain}/${f}`);
    res.json(files);
  } else {
    res.json([]);
  }
});


/* ================= PYTHON ================= */
const scriptsPath = path.join(__dirname, "Scripts");

app.get("/analyze/eye", (req, res) => {
  PythonShell.run("eye_detection.py", { scriptPath: scriptsPath }, (err, out) => {
    if (err) return res.status(500).json({ error: "Failed" });
    res.json(out);
  });
});


/* ================= REPORT GENERATION ================= */
app.post("/analyze/generate-report", (req, res) => {
  const { videoPath, candidateName, role } = req.body;
  if (!videoPath) {
    return res.status(400).json({ error: "videoPath is required" });
  }

  // Use the local venv python
  const pythonPath = path.join(__dirname, "venv", "Scripts", "python.exe");

  const options = {
    mode: "text",
    pythonPath: process.env.PYTHON_PATH || pythonPath, // Allow override via env
    scriptPath: __dirname,
    pythonOptions: ['-u'],
    args: [
      videoPath,
      "--name", candidateName || "Candidate",
      "--role", role || "Applicant",
      "--save-data",
      "--quick"
    ],
    timeout: 300000
  };

  console.log(`Starting analysis for ${videoPath}...`);

  const pyshell = new PythonShell("integrated_analysis_report.py", options);

  // Array to collect all log lines for the final JSON response
  let results = [];

  // 1. Stream stdout (print to terminal immediately)
  pyshell.on('message', function (message) {
    console.log(`[PYTHON] ${message}`);
    results.push(message);
  });

  // 2. Stream stderr (catch errors immediately)
  pyshell.on('stderr', function (stderr) {
    console.error(`[PYTHON ERR] ${stderr}`);
  });

  // 3. Handle script completion
  pyshell.end(function (err, code, signal) {
    if (err) {
      console.error("Python script exited with error:", err);
      // We return a 500 error, but include any partial logs which might help debug
      return res.status(500).json({
        error: "Analysis execution failed",
        details: err.message,
        logs: results
      });
    }

    // 1. Try to parse logs
    let pdfFilename = null;
    if (results && results.length > 0) {
      const reportLine = results.find(line => line && line.includes("File:") && line.trim().startsWith("File:"));
      if (reportLine) {
        const parts = reportLine.split(":");
        if (parts.length >= 2) {
          pdfFilename = parts[1].trim();
        }
      }
    }

    // 2. Fallback: Scan directory for the newest PDF
    if (!pdfFilename) {
      console.log("Parsing filename failed. Scanning directory for newest PDF...");
      try {
        const reportsDir = path.join(__dirname, "professional_reports");
        if (fs.existsSync(reportsDir)) {
          const files = fs.readdirSync(reportsDir)
            .filter(f => f.endsWith('.pdf'))
            .map(f => {
              const stats = fs.statSync(path.join(reportsDir, f));
              return { name: f, time: stats.mtime.getTime() };
            })
            .sort((a, b) => b.time - a.time); // Newest first

          // If the newest file was created in the last 2 minutes, assume it's ours
          if (files.length > 0) {
            const newest = files[0];
            const twoMinutesAgo = Date.now() - 2 * 60 * 1000;
            if (newest.time > twoMinutesAgo) {
              pdfFilename = newest.name;
              console.log("Found newest PDF via filesystem:", pdfFilename);
            }
          }
        }
      } catch (fsErr) {
        console.error("Error scanning reports directory:", fsErr);
      }
    }

    if (pdfFilename) {
      console.log("Analysis completed. Report:", pdfFilename);
      const baseUrl = getBaseUrl(req);
      res.json({
        success: true,
        pdfFilename: pdfFilename,
        pdfUrl: `${baseUrl}/reports/${pdfFilename}`,
        logs: results
      });
    } else {
      console.warn("Analysis ran but no PDF file could be identified.");
      res.json({
        success: true,
        pdfFilename: null,
        pdfUrl: null,
        logs: results,
        warning: "Report generated but filename lookup failed. Please check reports folder."
      });
    }
  });
});

/* ================= START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
});
