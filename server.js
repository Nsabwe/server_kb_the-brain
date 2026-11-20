/**
 * KB Yaza Brain — Backend (Login + Signup only)
 * Endpoints:
 *   GET  /                    -> health + MongoDB connection status
 *   POST /api/auth/signup     -> create account
 *   POST /api/auth/login      -> login
 *   GET  /api/auth/me         -> (optional) current user from token
 */

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

/* =========================================================
   MIDDLEWARE
   ========================================================= */
app.use(express.json({ limit: "1mb" }));
app.use(
  cors({
    origin: "*", // tighten this to your frontend URL in production
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

/* =========================================================
   ENV
   ========================================================= */
const PORT = process.env.PORT || 10000;
const MONGO_URI = process.env.MONGO_URI || "";
const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-render-env";
const JWT_EXPIRES = "30d";

/* =========================================================
   MONGOOSE — USER MODEL
   ========================================================= */
const userSchema = new mongoose.Schema(
  {
    name: { type: String, trim: true },
    email: { type: String, trim: true, lowercase: true, sparse: true, unique: true },
    phone: { type: String, trim: true, sparse: true, unique: true },
    passwordHash: { type: String, required: true },
    hasPlan: { type: Boolean, default: false },
    planExpiresAt: { type: Date, default: null },
  },
  { timestamps: true }
);

userSchema.methods.toSafeJSON = function () {
  return {
    id: this._id,
    name: this.name || null,
    email: this.email || null,
    phone: this.phone || null,
    hasPlan: this.hasPlan,
    planExpiresAt: this.planExpiresAt,
  };
};

const User = mongoose.model("User", userSchema);

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
    console.error("❌ MONGO_URI is not set. Set it in Render → Environment.");
    return;
  }
  try {
    console.log("⏳ Connecting to MongoDB…");
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 15000,
    });
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
  console.warn("⚠️  MongoDB disconnected");
});
mongoose.connection.on("reconnected", () => {
  dbState.connected = true;
  dbState.status = "connected";
  console.log("🔁 MongoDB reconnected");
});

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

function isValidEmail(v) {
  return typeof v === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim());
}

function isValidPin(v) {
  return typeof v === "string" && /^\d{4}$/.test(v);
}

function signToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), email: user.email || null, phone: user.phone || null },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

function authResponse(user) {
  return {
    token: signToken(user),
    user: user.toSafeJSON(),
    hasPlan: user.hasPlan,
    planExpiresAt: user.planExpiresAt,
  };
}

/* =========================================================
   ROUTES — HEALTH / DB STATUS
   ========================================================= */
app.get("/", (req, res) => {
  const ok = dbState.connected;
  res.status(ok ? 200 : 503).json({
    service: "KB Yaza Brain API",
    status: ok ? "ok" : "degraded",
    mongodb: {
      connected: dbState.connected,
      state: dbState.status,
      database: dbState.name,
      host: dbState.host,
      connectedAt: dbState.connectedAt,
      error: dbState.error,
    },
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

/* =========================================================
   ROUTES — AUTH
   ========================================================= */

/**
 * POST /api/auth/signup
 * Body (phone method): { name, phone, password, method: "phone" }
 * Body (email method): { name, email, password, method: "email" }
 * password = 4-digit PIN
 */
app.post("/api/auth/signup", async (req, res) => {
  try {
    if (!dbState.connected) {
      return res.status(503).json({ message: "Database not connected. Try again shortly." });
    }

    let { name, email, phone, password, method } = req.body || {};

    // Determine method
    if (!method) method = email ? "email" : phone ? "phone" : null;

    if (!isValidPin(password)) {
      return res.status(400).json({ message: "PIN must be exactly 4 digits" });
    }

    let query = null;
    let data = { name: (name || "").trim() || undefined, passwordHash: null };

    if (method === "email") {
      if (!isValidEmail(email)) {
        return res.status(400).json({ message: "Enter a valid email" });
      }
      data.email = email.trim().toLowerCase();
      query = { email: data.email };
    } else if (method === "phone") {
      const normalized = normalizePhone(phone);
      if (!normalized) {
        return res.status(400).json({ message: "Enter a valid Malawi phone number" });
      }
      data.phone = normalized;
      query = { phone: data.phone };
    } else {
      return res.status(400).json({ message: "Provide email or phone" });
    }

    const existing = await User.findOne(query);
    if (existing) {
      return res.status(409).json({
        message: method === "email"
          ? "An account with this email already exists"
          : "An account with this phone already exists",
      });
    }

    data.passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create(data);
    console.log(`🆕 Signup: ${user.email || user.phone}`);

    return res.status(201).json(authResponse(user));
  } catch (err) {
    // Duplicate key (race condition)
    if (err.code === 11000) {
      return res.status(409).json({ message: "Account already exists" });
    }
    console.error("Signup error:", err);
    return res.status(500).json({ message: "Server error during signup" });
  }
});

/**
 * POST /api/auth/login
 * Body (phone): { phone, password, method: "phone" }
 * Body (email): { email, password, method: "email" }
 */
app.post("/api/auth/login", async (req, res) => {
  try {
    if (!dbState.connected) {
      return res.status(503).json({ message: "Database not connected. Try again shortly." });
    }

    let { email, phone, password, method } = req.body || {};
    if (!method) method = email ? "email" : phone ? "phone" : null;

    if (!isValidPin(password)) {
      return res.status(400).json({ message: "PIN must be exactly 4 digits" });
    }

    let user = null;
    if (method === "email") {
      if (!isValidEmail(email)) {
        return res.status(400).json({ message: "Enter a valid email" });
      }
      user = await User.findOne({ email: email.trim().toLowerCase() });
    } else if (method === "phone") {
      const normalized = normalizePhone(phone);
      if (!normalized) {
        return res.status(400).json({ message: "Enter a valid Malawi phone number" });
      }
      user = await User.findOne({ phone: normalized });
    } else {
      return res.status(400).json({ message: "Provide email or phone" });
    }

    if (!user) {
      return res.status(401).json({ message: "Incorrect email/phone or PIN" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ message: "Incorrect email/phone or PIN" });
    }

    console.log(`🔐 Login: ${user.email || user.phone}`);
    return res.json(authResponse(user));
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error during login" });
  }
});

/* =========================================================
   OPTIONAL: /api/auth/me (validate token)
   ========================================================= */
app.get("/api/auth/me", async (req, res) => {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: "No token" });

    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ message: "User not found" });

    return res.json(authResponse(user));
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
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
    console.log(`🚀 Server listening on port ${PORT}`);
    console.log(`   Health check: http://localhost:${PORT}/`);
  });
})();