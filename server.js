/**
 * KB Yaza Brain — Full Backend
 * ─────────────────────────────
 * Frontend contract (matches index.html):
 *   GET  /                       → books array
 *   GET  /:id/download           → { url, filename }  (JWT + plan)
 *   POST /api/auth/signup        → phone + PIN
 *   POST /api/auth/login         → phone + PIN
 *   POST /api/auth/reset-pin     → name + phone + newPassword
 *   POST /api/pay                → creates payment
 *   GET  /api/pay/status?ref=…   → poll payment
 *
 * Admin contract (matches admin.html):
 *   POST /api/admin/books        → multipart upload → Cloudinary → Mongo
 *   GET  /api/admin/ping         → sanity check
 *
 * Monitoring:
 *   GET  /health                 → DB status
 */

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const crypto = require("crypto");
const { Readable } = require("stream");
const cloudinary = require("cloudinary").v2;

const app = express();

/* =========================================================
   ENV
   ========================================================= */
const PORT = process.env.PORT || 10000;
const MONGO_URI = process.env.MONGO_URI || "";
const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const JWT_EXPIRES = "30d";
const ADMIN_KEY = process.env.ADMIN_KEY || "change-admin-key";
const PLAN_PRICE_MWK = 500;
const PLAN_DAYS = 30;

/* =========================================================
   MIDDLEWARE
   ========================================================= */
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"],
  })
);
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   CLOUDINARY
   ========================================================= */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok =
      file.mimetype === "application/pdf" ||
      file.mimetype === "image/jpeg" ||
      file.mimetype === "image/png";
    if (!ok) return cb(new Error("Only PDF, JPG, PNG allowed"));
    cb(null, true);
  },
});

function uploadBufferToCloudinary(buffer, options) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(options, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    });
    Readable.from(buffer).pipe(stream);
  });
}

/* =========================================================
   MONGOOSE MODELS
   ========================================================= */
const userSchema = new mongoose.Schema(
  {
    name: { type: String, trim: true },
    phone: { type: String, trim: true, unique: true, required: true, index: true },
    passwordHash: { type: String, required: true },
    hasPlan: { type: Boolean, default: false },
    planExpiresAt: { type: Date, default: null },
    downloads: [
      {
        bookId: { type: mongoose.Schema.Types.ObjectId, ref: "Book" },
        at: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

userSchema.methods.toSafeJSON = function () {
  return {
    id: this._id,
    name: this.name || null,
    phone: this.phone,
    email: null,
    hasPlan: this.hasPlan,
    planExpiresAt: this.planExpiresAt,
  };
};

userSchema.methods.hasActivePlan = function () {
  if (!this.hasPlan) return false;
  if (!this.planExpiresAt) return true;
  return new Date(this.planExpiresAt) > new Date();
};

const User = mongoose.model("User", userSchema);

const bookSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    subject: { type: String, required: true, trim: true, index: true },
    form: { type: Number, required: true, min: 1, max: 4, index: true },
    pdfUrl: { type: String, required: true },
    coverUrl: { type: String, default: "" },
    sizeBytes: { type: Number, default: 0 },
    uploadedBy: { type: String, default: "admin" },
  },
  { timestamps: true }
);

const Book = mongoose.model("Book", bookSchema);

const paymentSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    amount: { type: Number, required: true },
    currency: { type: String, default: "MWK" },
    reference: { type: String, unique: true, index: true },
    status: {
      type: String,
      enum: ["pending", "paid", "failed", "cancelled"],
      default: "pending",
      index: true,
    },
    paidAt: { type: Date, default: null },
  },
  { timestamps: true }
);

const Payment = mongoose.model("Payment", paymentSchema);

/* =========================================================
   DB CONNECTION
   ========================================================= */
let dbState = {
  connected: false,
  status: "disconnected",
  name: null,
  host: null,
  error: null,
  connectedAt: null,
};

async function connectDB() {
  if (!MONGO_URI) {
    dbState.status = "no-uri";
    dbState.error = "MONGO_URI env var is not set";
    console.error("❌ MONGO_URI is not set");
    return;
  }
  try {
    console.log("⏳ Connecting to MongoDB…");
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 15000 });
    const { name, host } = mongoose.connection;
    dbState = {
      connected: true,
      status: "connected",
      name,
      host,
      error: null,
      connectedAt: new Date().toISOString(),
    };
    console.log(`✅ MongoDB connected → db="${name}" host="${host}"`);
    await seedBooksIfEmpty();
  } catch (err) {
    dbState.connected = false;
    dbState.status = "error";
    dbState.error = err.message;
    console.error("❌ MongoDB connection error:", err.message);
  }
}

mongoose.connection.on("disconnected", () => {
  dbState.connected = false;
  dbState.status = "disconnected";
});
mongoose.connection.on("reconnected", () => {
  dbState.connected = true;
  dbState.status = "connected";
});

/* =========================================================
   SEED BOOKS (only on first empty run)
   ========================================================= */
async function seedBooksIfEmpty() {
  try {
    if ((await Book.countDocuments()) > 0) return;
    const subjects = [
      "English", "Chichewa", "Mathematics", "Biology", "Agriculture",
      "Chemistry", "Physics", "Geography", "History", "Social Studies",
    ];
    const samplePdf =
      "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf";
    const docs = [];
    for (let form = 1; form <= 4; form++) {
      for (const s of subjects) {
        docs.push({
          title: `${s} Form ${form}`,
          subject: s,
          form,
          pdfUrl: samplePdf,
          coverUrl: "",
        });
      }
    }
    await Book.insertMany(docs);
    console.log(`🌱 Seeded ${docs.length} demo books`);
  } catch (e) {
    console.error("Seed error:", e.message);
  }
}

/* =========================================================
   HELPERS
   ========================================================= */
function normalizePhone(raw) {
  if (!raw) return null;
  let p = String(raw).replace(/[\s\-()]/g, "");
  if (/^0\d{9}$/.test(p)) return "+265" + p.slice(1);
  if (/^265\d{9}$/.test(p)) return "+" + p;
  if (/^\+265\d{9}$/.test(p)) return p;
  if (/^\d{9}$/.test(p)) return "+265" + p;
  return null;
}

function isValidPin(v) {
  return typeof v === "string" && /^\d{4}$/.test(v);
}

function signToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), phone: user.phone },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

function authResponse(user) {
  return {
    token: signToken(user),
    user: user.toSafeJSON(),
    hasPlan: user.hasActivePlan(),
    planExpiresAt: user.planExpiresAt,
  };
}

function publicBook(b) {
  return {
    _id: b._id,
    title: b.title,
    subject: b.subject,
    form: b.form,
    pdfUrl: b.pdfUrl,
    coverUrl: b.coverUrl || "",
  };
}

/* =========================================================
   MIDDLEWARE — AUTH / ADMIN
   ========================================================= */
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: "Missing token" });

    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ message: "User not found" });

    req.user = user;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

function requireAdmin(req, res, next) {
  const key = req.headers["x-admin-key"] || req.query.adminKey;
  if (key !== ADMIN_KEY) {
    return res.status(403).json({ message: "Forbidden — wrong admin key" });
  }
  next();
}

/* =========================================================
   HEALTH
   ========================================================= */
app.get("/health", (req, res) => {
  const ok = dbState.connected;
  res.status(ok ? 200 : 503).json({
    service: "KB Yaza Brain API",
    version: "3.0.0",
    status: ok ? "ok" : "degraded",
    mongodb: {
      connected: dbState.connected,
      state: dbState.status,
      database: dbState.name,
      host: dbState.host,
      connectedAt: dbState.connectedAt,
      error: dbState.error,
    },
    cloudinary: {
      cloud: process.env.CLOUDINARY_CLOUD_NAME || "(missing)",
      apiKey: process.env.CLOUDINARY_API_KEY ? "set" : "MISSING",
      apiSecret: process.env.CLOUDINARY_API_SECRET ? "set" : "MISSING",
    },
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

/* =========================================================
   AUTH ROUTES
   ========================================================= */

// POST /api/auth/signup
app.post("/api/auth/signup", async (req, res) => {
  try {
    if (!dbState.connected) return res.status(503).json({ message: "DB offline" });

    const { name, phone, password } = req.body || {};
    const normalized = normalizePhone(phone);
    if (!normalized) return res.status(400).json({ message: "Enter a valid Malawi phone number" });
    if (!isValidPin(password)) return res.status(400).json({ message: "PIN must be exactly 4 digits" });

    if (await User.findOne({ phone: normalized })) {
      return res.status(409).json({ message: "An account with this phone already exists" });
    }

    const user = await User.create({
      name: (name || "").trim() || undefined,
      phone: normalized,
      passwordHash: await bcrypt.hash(password, 10),
    });

    console.log(`🆕 Signup: ${user.phone}`);
    res.status(201).json(authResponse(user));
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ message: "Account already exists" });
    console.error("Signup error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
  try {
    if (!dbState.connected) return res.status(503).json({ message: "DB offline" });

    const { phone, password } = req.body || {};
    const normalized = normalizePhone(phone);
    if (!normalized) return res.status(400).json({ message: "Enter a valid Malawi phone number" });
    if (!isValidPin(password)) return res.status(400).json({ message: "PIN must be exactly 4 digits" });

    const user = await User.findOne({ phone: normalized });
    if (!user) return res.status(401).json({ message: "Incorrect phone or PIN" });

    if (!(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ message: "Incorrect phone or PIN" });
    }

    console.log(`🔐 Login: ${user.phone}`);
    res.json(authResponse(user));
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// POST /api/auth/reset-pin
app.post("/api/auth/reset-pin", async (req, res) => {
  try {
    if (!dbState.connected) return res.status(503).json({ message: "DB offline" });

    const { name, phone, newPassword } = req.body || {};
    if (!name || name.trim().length < 2) {
      return res.status(400).json({ message: "Please provide your registered name" });
    }
    const normalized = normalizePhone(phone);
    if (!normalized) return res.status(400).json({ message: "Enter a valid Malawi phone number" });
    if (!isValidPin(newPassword)) {
      return res.status(400).json({ message: "New PIN must be exactly 4 digits" });
    }

    const user = await User.findOne({ phone: normalized });
    if (!user) return res.status(404).json({ message: "No account found for this phone" });
    if (!user.name || user.name.trim().toLowerCase() !== name.trim().toLowerCase()) {
      return res.status(401).json({ message: "Name does not match our records" });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ ok: true, message: "PIN reset successful" });
  } catch (err) {
    console.error("Reset PIN error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET /api/auth/me
app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json(authResponse(req.user));
});

/* =========================================================
   PAYMENTS
   ========================================================= */
app.post("/api/pay", requireAuth, async (req, res) => {
  try {
    if (!dbState.connected) return res.status(503).json({ message: "DB offline" });

    const amount = Number(req.body?.amount || PLAN_PRICE_MWK);
    if (amount < 1) return res.status(400).json({ message: "Invalid amount" });

    const reference = "KBY-" + crypto.randomBytes(6).toString("hex").toUpperCase();

    const payment = await Payment.create({
      userId: req.user._id,
      amount,
      currency: req.body?.currency || "MWK",
      reference,
      status: "pending",
    });

    // Demo auto-confirm after 10 s (plug real Airtel/TNM here later)
    setTimeout(async () => {
      try {
        const p = await Payment.findById(payment._id);
        if (p && p.status === "pending") {
          p.status = "paid";
          p.paidAt = new Date();
          await p.save();
          const u = await User.findById(p.userId);
          if (u) {
            u.hasPlan = true;
            u.planExpiresAt = new Date(Date.now() + PLAN_DAYS * 864e5);
            await u.save();
            console.log(`💳 Auto-confirmed ${p.reference}`);
          }
        }
      } catch (e) {
        console.error("Auto-confirm:", e.message);
      }
    }, 10000);

    res.json({
      reference,
      status: "pending",
      amount,
      currency: payment.currency,
      message: "Approve payment on your phone",
    });
  } catch (err) {
    console.error("Pay error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/pay/status", requireAuth, async (req, res) => {
  try {
    const ref = String(req.query.ref || "").trim();
    if (!ref) return res.status(400).json({ message: "Missing ref" });

    const p = await Payment.findOne({ reference: ref, userId: req.user._id });
    if (!p) return res.status(404).json({ message: "Payment not found" });

    res.json({
      reference: p.reference,
      status: p.status,
      amount: p.amount,
      currency: p.currency,
      paidAt: p.paidAt,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Dev helper — force a payment to paid
app.post("/api/pay/:ref/simulate", requireAdmin, async (req, res) => {
  try {
    const p = await Payment.findOne({ reference: req.params.ref });
    if (!p) return res.status(404).json({ message: "Not found" });

    p.status = "paid";
    p.paidAt = new Date();
    await p.save();

    const u = await User.findById(p.userId);
    if (u) {
      u.hasPlan = true;
      u.planExpiresAt = new Date(Date.now() + PLAN_DAYS * 864e5);
      await u.save();
    }
    res.json({ ok: true, reference: p.reference, status: p.status });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================================================
   ADMIN — UPLOAD BOOK (multipart: pdf, cover)
   ========================================================= */
app.get("/api/admin/ping", requireAdmin, (req, res) => {
  res.json({ ok: true, message: "Admin key is valid ✅" });
});

app.post(
  "/api/admin/books",
  requireAdmin,
  upload.fields([
    { name: "pdf", maxCount: 1 },
    { name: "cover", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      if (!dbState.connected) return res.status(503).json({ message: "DB offline" });

      const { title, subject, form } = req.body || {};
      if (!title || !subject || !form) {
        return res.status(400).json({ message: "title, subject, form are required" });
      }

      const pdfFile = req.files?.pdf?.[0];
      if (!pdfFile) return res.status(400).json({ message: "PDF file is required" });

      console.log(`☁️  Uploading PDF: ${pdfFile.originalname}`);
      const pdfResult = await uploadBufferToCloudinary(pdfFile.buffer, {
        resource_type: "raw",
        folder: "kbyaza/books",
        public_id: `book_${Date.now()}_${crypto.randomBytes(3).toString("hex")}`,
        format: "pdf",
      });

      let coverUrl = "";
      const coverFile = req.files?.cover?.[0];
      if (coverFile) {
        console.log(`☁️  Uploading cover: ${coverFile.originalname}`);
        const coverResult = await uploadBufferToCloudinary(coverFile.buffer, {
          resource_type: "image",
          folder: "kbyaza/covers",
          transformation: [{ width: 400, height: 600, crop: "fill" }],
        });
        coverUrl = coverResult.secure_url;
      }

      const book = await Book.create({
        title: title.trim(),
        subject: subject.trim(),
        form: Number(form),
        pdfUrl: pdfResult.secure_url,
        coverUrl,
        sizeBytes: pdfFile.size,
      });

      console.log(`📚 Book saved: ${book.title} → ${book.pdfUrl}`);
      res.status(201).json({ ok: true, book: publicBook(book) });
    } catch (err) {
      console.error("Admin upload error:", err);
      res.status(500).json({ message: err.message || "Upload failed" });
    }
  }
);

/* =========================================================
   BOOKS — served at root to match frontend
   ========================================================= */

// Alias: GET /api/books
app.get("/api/books", async (req, res) => {
  try {
    if (!dbState.connected) return res.status(503).json({ message: "DB offline" });
    const books = await Book.find().sort({ form: 1, subject: 1, title: 1 }).lean();
    res.json(books.map(publicBook));
  } catch (err) {
    console.error("Books list:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET /  → books array (matches frontend's `fetch(API.BOOKS)`)
app.get("/", async (req, res) => {
  try {
    if (!dbState.connected) {
      return res.status(503).json({ message: "Database not connected", books: [] });
    }
    const books = await Book.find().sort({ form: 1, subject: 1, title: 1 }).lean();
    res.json(books.map(publicBook));
  } catch (err) {
    console.error("Books list:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET /:id  → single book (optional)
app.get("/:id", async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid book id" });
    }
    const book = await Book.findById(req.params.id).lean();
    if (!book) return res.status(404).json({ message: "Book not found" });
    res.json(publicBook(book));
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

// GET /:id/download  → returns { url, filename } (JWT + plan required)
app.get("/:id/download", requireAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid book id" });
    }
    if (!req.user.hasActivePlan()) {
      return res.status(402).json({ message: "Active plan required" });
    }
    const book = await Book.findById(req.params.id);
    if (!book) return res.status(404).json({ message: "Book not found" });

    req.user.downloads.push({ bookId: book._id });
    await req.user.save();

    res.json({
      url: book.pdfUrl,
      filename: `${book.title.replace(/[^\w\s-]/g, "")}.pdf`,
    });
  } catch (err) {
    console.error("Download error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================================================
   404
   ========================================================= */
app.use((req, res) => {
  res.status(404).json({ message: `Route not found: ${req.method} ${req.path}` });
});

/* =========================================================
   START
   ========================================================= */
(async () => {
  await connectDB();
  app.listen(PORT, () => {
    console.log(`🚀 Listening on port ${PORT}`);
    console.log(`   Health : http://localhost:${PORT}/health`);
    console.log(`   Books  : http://localhost:${PORT}/`);
  });
})();