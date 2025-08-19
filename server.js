import express from "express";
import session from "express-session";
import helmet from "helmet";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";
import { v4 as uuidv4 } from "uuid";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const DB_PATH = process.env.DB_PATH || "cotillion.db";
const db = new Database(DB_PATH);

const ACCESS_PASSWORD = process.env.ACCESS_PASSWORD || "change-me";
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-please-change";
const PORT = process.env.PORT || 3000;

// Security / middleware
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: "lax", httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use("/public", express.static(path.join(__dirname, "public")));

// DB init
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    code_hash TEXT NOT NULL,
    gender TEXT CHECK(gender IN ('girl','guy')),
    partner_id INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS asks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','accepted','declined','canceled')),
    message TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);
try {
  db.prepare("ALTER TABLE users ADD COLUMN gender TEXT CHECK(gender IN ('girl','guy'))").run();
} catch (e) {}

// helpers
const sanitizeName = (s) => (s || "").trim().replace(/\s+/g, " ").slice(0, 40);
const normalizeGender = (g) => {
  const v = String(g || "").toLowerCase().trim();
  if (["girl","female","f"].includes(v)) return "girl";
  if (["guy","male","m"].includes(v)) return "guy";
  return null;
};
const requireAccess = (req,res,next)=>{
  if (req.path === "/access" || req.path === "/enter" || req.path === "/") return next();
  if (!req.session?.accessGranted) return res.redirect("/access");
  next();
};
const requireAccessApi=(req,res,next)=>{
  if (!req.session?.accessGranted) return res.status(403).json({error:"Access denied"});
  next();
};
const requireUser=(req,res,next)=>{
  if (!req.session?.userId) return res.status(401).json({error:"Not signed in"});
  next();
};
const ensureCsrf=(req,res,next)=>{
  if (!req.session.csrf) req.session.csrf=uuidv4();
  const safe=req.method==="GET"||req.method==="HEAD";
  if (safe) return next();
  const token=req.headers["x-csrf-token"];
  if (token!==req.session.csrf) return res.status(403).json({error:"Bad CSRF token"});
  next();
};

// access page
app.get("/access",(req,res)=>{
  res.type("html").send(`<!doctype html>
<html><body><form method="POST" action="/enter">
<h1>Enter Site Passcode</h1>
<input name="password" type="password" />
<button type="submit">Enter</button>
</form></body></html>`);
});
app.post("/enter",(req,res)=>{
  const {password}=req.body||{};
  if(password===ACCESS_PASSWORD){req.session.accessGranted=true;req.session.csrf=uuidv4();return res.redirect("/");}
  res.status(401).send("Wrong passcode.");
});

// main app
app.use(requireAccess);
app.get("/",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

// API
app.use("/api",requireAccessApi,ensureCsrf);

app.get("/api/csrf",(req,res)=>{if(!req.session.csrf)req.session.csrf=uuidv4();res.json({csrf:req.session.csrf});});

// signup
app.post("/api/signup",async(req,res)=>{
  const name=sanitizeName(req.body?.name);
  const code=(req.body?.code||"").trim();
  const gender=normalizeGender(req.body?.gender);
  if(!name||code.length<4) return res.status(400).json({error:"Invalid name or code"});
  if(!gender) return res.status(400).json({error:"Pick girl or guy"});
  try{
    const hash=await bcrypt.hash(code,10);
    db.prepare("INSERT INTO users (name,code_hash,gender) VALUES (?,?,?)").run(name,hash,gender);
    const user=db.prepare("SELECT id,name,partner_id,gender FROM users WHERE name=?").get(name);
    req.session.userId=user.id;
    res.json({ok:true,user});
  }catch(e){
    if(String(e).includes("UNIQUE")) return res.status(409).json({error:"Name already taken"});
    res.status(500).json({error:"Server error"});
  }
});

// signin
app.post("/api/signin",async(req,res)=>{
  const name=sanitizeName(req.body?.name);
  const code=(req.body?.code||"").trim();
  const user=db.prepare("SELECT * FROM users WHERE name=?").get(name);
  if(!user) return res.status(400).json({error:"No such user"});
  const ok=await bcrypt.compare(code,user.code_hash);
  if(!ok) return res.status(401).json({error:"Wrong code"});
  req.session.userId=user.id;
  res.json({ok:true,user:{id:user.id,name:user.name,partner_id:user.partner_id,gender:user.gender}});
});

app.post("/api/signout",(req,res)=>{req.session.userId=null;res.json({ok:true});});
app.get("/api/me",(req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:"Not signed in"});
  const me=db.prepare("SELECT id,name,partner_id,gender FROM users WHERE id=?").get(req.session.userId);
  res.json({me});
});

app.get("/api/members",(req,res)=>{
  const users=db.prepare("SELECT id,name,partner_id,gender FROM users").all();
  const idToName=Object.fromEntries(users.map(u=>[u.id,u.name]));
  res.json({members:users.map(u=>({id:u.id,name:u.name,gender:u.gender,partnerId:u.partner_id,partnerName:u.partner_id?idToName[u.partner_id]:null}))});
});

function userIsMatched(id){return !!db.prepare("SELECT partner_id FROM users WHERE id=?").get(id)?.partner_id;}

app.post("/api/ask",(req,res)=>{
  const fromId=req.session.userId;const toId=Number(req.body?.toUserId||0);const msg=(req.body?.message||"").slice(0,280);
  const from=db.prepare("SELECT gender FROM users WHERE id=?").get(fromId);
  const to=db.prepare("SELECT gender FROM users WHERE id=?").get(toId);
  if(!(from?.gender==="girl"&&to?.gender==="guy")) return res.status(403).json({error:"Only girls can ask out guys"});
  if(userIsMatched(fromId)||userIsMatched(toId)) return res.status(400).json({error:"Already taken"});
  db.prepare("INSERT INTO asks (uuid,from_user_id,to_user_id,status,message) VALUES (?,?,?,?,?)")
    .run(uuidv4(),fromId,toId,"pending",msg);
  res.json({ok:true});
});

// listen
app.listen(PORT,()=>console.log("Running on http://localhost:"+PORT));