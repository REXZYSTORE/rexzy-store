import "dotenv/config";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import nodemailer from "nodemailer";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import {fileURLToPath} from "url";

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express(), PORT=Number(process.env.PORT||3000);
const dataDir=path.join(__dirname,"../data"); fs.mkdirSync(dataDir,{recursive:true});
if(!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length<32) throw new Error("SESSION_SECRET must be 32+ chars");

const db=new Database(path.join(dataDir,"rexzygo.sqlite"));
db.pragma("journal_mode=WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member',
 membership TEXT NOT NULL DEFAULT 'standard', balance INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS otp(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,code_hash TEXT NOT NULL,
 expires_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,used INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS services(
 id INTEGER PRIMARY KEY AUTOINCREMENT,platform TEXT NOT NULL,name TEXT NOT NULL,
 unit TEXT NOT NULL,price INTEGER NOT NULL,active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS orders(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,service_id INTEGER NOT NULL,
 target TEXT NOT NULL,quantity INTEGER NOT NULL,total INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS topups(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,amount INTEGER NOT NULL,
 method TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',external_id TEXT,created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vip_purchases(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,amount INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',external_id TEXT,created_at TEXT NOT NULL
);
`);
const iso=()=>new Date().toISOString(), sha=x=>crypto.createHash("sha256").update(x).digest("hex");
const token=()=>crypto.randomBytes(32).toString("hex");
const cookieOpts={httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*86400000};

if(process.env.OWNER_USERNAME&&process.env.OWNER_EMAIL&&process.env.OWNER_PASSWORD){
 const email=process.env.OWNER_EMAIL.toLowerCase();
 if(!db.prepare("SELECT id FROM users WHERE email=?").get(email)){
  db.prepare("INSERT INTO users(username,email,password_hash,role,created_at) VALUES(?,?,?,?,?)")
   .run(process.env.OWNER_USERNAME,email,bcrypt.hashSync(process.env.OWNER_PASSWORD,12),"owner",iso());
 }
}
if(db.prepare("SELECT COUNT(*) c FROM services").get().c===0){
 const seed=[
  ["TikTok","Followers TikTok","per 100",2000],["TikTok","Likes TikTok","per 1000",1500],
  ["Instagram","Followers Instagram","per 100",2500],["Instagram","Likes Instagram","per 1000",1500],
  ["WhatsApp","Member Channel","per 100",3000],["WhatsApp","Views Channel","per 1000",2000]
 ];
 const q=db.prepare("INSERT INTO services(platform,name,unit,price) VALUES(?,?,?,?)");
 db.transaction(()=>seed.forEach(x=>q.run(...x)))();
}
let mailer=null;
if(process.env.SMTP_HOST&&process.env.SMTP_USER&&process.env.SMTP_PASS){
 mailer=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),
 secure:String(process.env.SMTP_SECURE)==="true",auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
}
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"100kb"}));
app.use(cookieParser());
app.use(rateLimit({windowMs:15*60*1000,max:300}));
app.use(express.static(path.join(__dirname,"../public")));

function auth(req,res,next){
 const raw=req.cookies.rgx_session;if(!raw)return res.status(401).json({error:"Belum login"});
 const u=db.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
 WHERE s.token_hash=? AND s.expires_at>?`).get(sha(raw),Date.now());
 if(!u)return res.status(401).json({error:"Sesi tidak valid"});
 req.user=u;next();
}
function owner(req,res,next){if(req.user.role!=="owner")return res.status(403).json({error:"Akses Owner saja"});next()}
function gmail(e){return /^[^\s@]+@gmail\.com$/i.test(e)}
async function sendOtp(user,code){
 if(!mailer)throw new Error("SMTP belum dikonfigurasi");
 await mailer.sendMail({from:process.env.MAIL_FROM,to:user.email,subject:"Kode OTP RexzyGo",
 text:`Kode OTP RexzyGo Anda: ${code}. Berlaku 10 menit dan hanya dapat digunakan sekali.`});
}

app.post("/api/auth/register",async(req,res)=>{
 const {username,email,password}=req.body||{};
 if(!username||!gmail(email)||!password||password.length<8)return res.status(400).json({error:"Username, Gmail, dan password minimal 8 karakter wajib diisi."});
 if(db.prepare("SELECT id FROM users WHERE username=? OR email=?").get(username,email.toLowerCase()))return res.status(409).json({error:"Username atau Gmail sudah digunakan."});
 const r=db.prepare("INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)")
 .run(username,email.toLowerCase(),await bcrypt.hash(password,12),iso());
 res.json({ok:true,id:r.lastInsertRowid});
});
app.post("/api/auth/login",async(req,res)=>{
 try{
  const {username,email,password}=req.body||{},u=db.prepare("SELECT * FROM users WHERE username=? AND email=?").get(username,(email||"").toLowerCase());
  if(!u||!(await bcrypt.compare(password||"",u.password_hash)))return res.status(401).json({error:"Login salah"});
  if(!mailer)return res.status(503).json({error:"SMTP belum aktif di server"});
  const code=String(crypto.randomInt(100000,1000000));
  db.prepare("UPDATE otp SET used=1 WHERE user_id=? AND used=0").run(u.id);
  db.prepare("INSERT INTO otp(user_id,code_hash,expires_at,created_at) VALUES(?,?,?,?)")
   .run(u.id,sha(code),Date.now()+600000,Date.now());
  await sendOtp(u,code);res.json({ok:true,otpRequired:true});
 }catch(e){console.error(e);res.status(500).json({error:"OTP gagal dikirim"});}
});
app.post("/api/auth/verify",async(req,res)=>{
 const {username,email,code}=req.body||{},u=db.prepare("SELECT * FROM users WHERE username=? AND email=?").get(username,(email||"").toLowerCase());
 if(!u)return res.status(401).json({error:"Akun tidak ditemukan"});
 const o=db.prepare("SELECT * FROM otp WHERE user_id=? AND used=0 ORDER BY id DESC LIMIT 1").get(u.id);
 if(!o||o.expires_at<Date.now()||o.attempts>=5)return res.status(401).json({error:"OTP kedaluwarsa/tidak valid"});
 db.prepare("UPDATE otp SET attempts=attempts+1 WHERE id=?").run(o.id);
 if(sha(String(code||""))!==o.code_hash)return res.status(401).json({error:"OTP salah"});
 db.prepare("UPDATE otp SET used=1 WHERE id=?").run(o.id);
 const raw=token();db.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").run(sha(raw),u.id,Date.now()+7*86400000);
 res.cookie("rgx_session",raw,cookieOpts).json({ok:true});
});
app.post("/api/auth/logout",auth,(req,res)=>{db.prepare("DELETE FROM sessions WHERE token_hash=?").run(sha(req.cookies.rgx_session));res.clearCookie("rgx_session").json({ok:true})});
app.get("/api/me",auth,(req,res)=>res.json({user:{username:req.user.username,email:req.user.email,role:req.user.role,membership:req.user.membership,balance:req.user.balance}}));
app.get("/api/services",(req,res)=>res.json(db.prepare("SELECT * FROM services WHERE active=1 ORDER BY id").all()));
app.get("/api/orders",auth,(req,res)=>res.json(db.prepare("SELECT o.*,s.name service_name FROM orders o JOIN services s ON s.id=o.service_id WHERE o.user_id=? ORDER BY o.id DESC").all(req.user.id)));
app.post("/api/orders",auth,(req,res)=>{
 const s=db.prepare("SELECT * FROM services WHERE id=? AND active=1").get(Number(req.body.serviceId));
 const qty=Number(req.body.quantity),target=String(req.body.target||"").trim();
 if(!s||!target||!Number.isInteger(qty)||qty<1)return res.status(400).json({error:"Order tidak valid"});
 const total=Math.ceil(qty/100)*s.price;
 try{
  const id=db.transaction(()=>{
   const u=db.prepare("SELECT balance FROM users WHERE id=?").get(req.user.id);if(u.balance<total)throw new Error("Saldo tidak cukup");
   db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(total,req.user.id);
   return db.prepare("INSERT INTO orders(user_id,service_id,target,quantity,total,created_at) VALUES(?,?,?,?,?,?)").run(req.user.id,s.id,target,qty,total,iso()).lastInsertRowid;
  })();res.json({ok:true,id});
 }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/topups",auth,(req,res)=>{
 const amount=Number(req.body.amount),method=String(req.body.method||"");
 if(!Number.isInteger(amount)||amount<10000)return res.status(400).json({error:"Nominal minimal Rp10.000"});
 const id=db.prepare("INSERT INTO topups(user_id,amount,method,created_at) VALUES(?,?,?,?)").run(req.user.id,amount,method,iso()).lastInsertRowid;
 res.json({ok:true,id,status:"pending"});
});
app.post("/api/vip/purchase",auth,(req,res)=>{
 const amount=Number(req.body.amount||5000);
 if(req.user.membership==="vip")return res.status(400).json({error:"Akun sudah VIP"});
 if(!Number.isInteger(amount)||amount<1000)return res.status(400).json({error:"Harga VIP tidak valid"});
 try{
  const id=db.transaction(()=>{
   const u=db.prepare("SELECT balance FROM users WHERE id=?").get(req.user.id);if(u.balance<amount)throw new Error("Saldo tidak cukup");
   db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(amount,req.user.id);
   return db.prepare("INSERT INTO vip_purchases(user_id,amount,status,created_at) VALUES(?,?,?,?)").run(req.user.id,amount,"pending",iso()).lastInsertRowid;
  })();res.json({ok:true,id,status:"pending",message:"Pembelian VIP menunggu konfirmasi Owner"});
 }catch(e){res.status(400).json({error:e.message})}
});

app.get("/api/admin/users",auth,owner,(req,res)=>res.json(db.prepare("SELECT id,username,email,role,membership,balance,created_at FROM users ORDER BY id DESC").all()));
app.get("/api/admin/topups",auth,owner,(req,res)=>res.json(db.prepare("SELECT t.*,u.username,u.email FROM topups t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC").all()));
app.get("/api/admin/vip",auth,owner,(req,res)=>res.json(db.prepare("SELECT v.*,u.username,u.email FROM vip_purchases v JOIN users u ON u.id=v.user_id ORDER BY v.id DESC").all()));
app.get("/api/admin/orders",auth,owner,(req,res)=>res.json(db.prepare("SELECT o.*,u.username,s.name service_name FROM orders o JOIN users u ON u.id=o.user_id JOIN services s ON s.id=o.service_id ORDER BY o.id DESC").all()));

app.post("/api/admin/topups/:id/approve",auth,owner,(req,res)=>{
 const t=db.prepare("SELECT * FROM topups WHERE id=?").get(Number(req.params.id));if(!t||t.status!=="pending")return res.status(400).json({error:"Top-up tidak tersedia"});
 db.transaction(()=>{db.prepare("UPDATE topups SET status='approved' WHERE id=?").run(t.id);db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(t.amount,t.user_id)})();res.json({ok:true});
});
app.post("/api/admin/vip/:id/approve",auth,owner,(req,res)=>{
 const v=db.prepare("SELECT * FROM vip_purchases WHERE id=?").get(Number(req.params.id));if(!v||v.status!=="pending")return res.status(400).json({error:"Pembelian VIP tidak tersedia"});
 db.transaction(()=>{db.prepare("UPDATE vip_purchases SET status='approved' WHERE id=?").run(v.id);db.prepare("UPDATE users SET membership='vip' WHERE id=?").run(v.user_id)})();res.json({ok:true});
});
app.post("/api/admin/orders/:id/status",auth,owner,(req,res)=>{
 const allowed=["pending","processing","completed","failed","cancelled"],s=String(req.body.status||"");
 if(!allowed.includes(s))return res.status(400).json({error:"Status invalid"});
 db.prepare("UPDATE orders SET status=? WHERE id=?").run(s,Number(req.params.id));res.json({ok:true});
});

/* Payment gateway adapter.
   DO NOT credit money unless the provider's official webhook signature is verified.
   Replace this handler with the exact verification scheme from your selected gateway. */
app.post("/api/payments/webhook/:provider",(req,res)=>{
 if(process.env.PAYMENT_WEBHOOK_SECRET){
  const supplied=req.get("x-webhook-secret")||"";
  if(supplied!==process.env.PAYMENT_WEBHOOK_SECRET)return res.status(401).end();
 }
 const {type,external_id,status,user_id,amount}=req.body||{};
 if(status!=="paid"||!Number.isInteger(Number(amount)))return res.status(400).json({error:"Webhook not accepted"});
 // Deliberately do not auto-credit here until the provider-specific signature verification is implemented.
 res.status(501).json({error:"Provider webhook verification must be implemented for the selected gateway before automatic crediting."});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"../public/index.html")));
app.listen(PORT,()=>console.log("RexzyGo V8 listening on "+PORT));
