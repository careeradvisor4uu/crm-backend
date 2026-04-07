const express  = require("express");
const mongoose = require("mongoose");
const cors     = require("cors");
const jwt      = require("jsonwebtoken");
const http     = require("http");
const { Server } = require("socket.io");

const app    = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));

mongoose.connect("mongodb://127.0.0.1:27017/crm")
  .then(() => console.log("MongoDB connected!"))
  .catch(err => console.log("MongoDB error:", err.message));

const SECRET        = "crm_secret_2024";
const CALLER_SECRET = "career2024";   // ← callers must enter this code to register

// ─── SCHEMAS ────────────────────────────────────────────────────────────────

const UserSchema = new mongoose.Schema({
  name:     String,
  email:    { type: String, unique: true },
  password: String,
  role:     { type: String, default: "caller" }
});
const User = mongoose.model("User", UserSchema);

const LeadSchema = new mongoose.Schema({
  name:          String,
  phone:         String,
  course:        String,
  college:       String,
  followUpDate:  String,
  callTime:      String,
  notes:         String,
  status:        { type: String, default: "New Lead" },
  assignedTo:    { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  createdAt:     { type: Date, default: Date.now }
});
const Lead = mongoose.model("Lead", LeadSchema);

// ─── AUTH MIDDLEWARE ─────────────────────────────────────────────────────────

const auth = (req, res, next) => {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(h.split(" ")[1], SECRET);
    next();
  } catch { res.status(401).json({ error: "Invalid token" }); }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
};

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

// Self-registration for callers only (requires secret code)
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, secretCode } = req.body;

    // Validate secret code
    if (secretCode !== CALLER_SECRET) {
      return res.json({ error: "Invalid secret code. Contact your admin." });
    }

    // Always register as caller (no admin self-registration)
    const user = await User.create({ name, email, password, role: "caller" });
    res.json({ message: "Account created successfully!", id: user._id });
  } catch (e) {
    res.json({ error: "Email already exists" });
  }
});

// Admin creation route (run once manually via POST, then disable or keep for internal use)
app.post("/api/create-admin", async (req, res) => {
  try {
    const { name, email, password, adminKey } = req.body;
    if (adminKey !== "ADMIN_MASTER_KEY_2024") {
      return res.status(403).json({ error: "Forbidden" });
    }
    const existing = await User.findOne({ role: "admin" });
    if (existing) return res.json({ error: "Admin already exists" });
    const user = await User.create({ name, email, password, role: "admin" });
    res.json({ message: "Admin created", id: user._id });
  } catch (e) {
    res.json({ error: e.message });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email, password });
  if (!user) return res.json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, SECRET, { expiresIn: "12h" });
  res.json({ token, user: { id: user._id, name: user.name, role: user.role } });
});

// ─── USERS ───────────────────────────────────────────────────────────────────

app.get("/api/users", auth, adminOnly, async (req, res) => {
  const users = await User.find({}, "-password");
  res.json(users);
});

// ─── LEADS ───────────────────────────────────────────────────────────────────

// GET leads — callers see only their own, admins see all
app.get("/api/leads", auth, async (req, res) => {
  const { search } = req.query;
  let query = {};

  if (req.user.role === "caller") {
    query.assignedTo = req.user.id;
  }

  if (search) {
    const searchConditions = [
      { name:  { $regex: search, $options: "i" } },
      { phone: { $regex: search, $options: "i" } }
    ];
    if (req.user.role === "caller") {
      query.$and = [{ assignedTo: req.user.id }, { $or: searchConditions }];
      delete query.assignedTo;
    } else {
      query.$or = searchConditions;
    }
  }

  const leads = await Lead.find(query)
    .populate("assignedTo", "name email")
    .sort({ createdAt: -1 });
  res.json(leads);
});

// POST single lead
app.post("/api/leads", auth, async (req, res) => {
  try {
    const lead = await Lead.create(req.body);
    const populated = await Lead.findById(lead._id).populate("assignedTo", "name email");
    res.json(populated);
  } catch (e) { res.json({ error: e.message }); }
});

// POST bulk leads (admin only)
app.post("/api/leads/bulk", auth, adminOnly, async (req, res) => {
  try {
    const { leads } = req.body;
    const inserted = await Lead.insertMany(leads);
    res.json({ message: `${inserted.length} leads imported`, count: inserted.length });
  } catch (e) { res.json({ error: e.message }); }
});

// PUT update lead
app.put("/api/leads/:id", auth, async (req, res) => {
  try {
    const lead = await Lead.findByIdAndUpdate(req.params.id, req.body, { new: true })
      .populate("assignedTo", "name email");
    res.json(lead);
  } catch (e) { res.json({ error: e.message }); }
});

// DELETE lead (admin only)
app.delete("/api/leads/:id", auth, adminOnly, async (req, res) => {
  await Lead.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});

// ─── SERVER ──────────────────────────────────────────────────────────────────

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

server.listen(5000, () => console.log("CRM Backend Running on port 5000"));
