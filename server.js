/**
 * ═══════════════════════════════════════════════════════════════
 *  Billsmart.id — Backend API Server v3.1 (FIXED)
 *  Stack: Node.js + Express + Supabase (PostgreSQL) + JWT + Nodemailer
 *
 *  PERBAIKAN:
 *  1. EMAIL_FROM sekarang pakai Gmail address (bukan noreply@billsmart.id)
 *  2. APP_URL otomatis detect dari request Host header (bukan hardcode localhost)
 *  3. SMTP error logging lebih detail (lihat console saat register)
 *  4. Tambah endpoint /api/menu/add, /api/menu/restock untuk dashboard buttons
 *  5. Tambah endpoint /api/report/export untuk cetak laporan
 *  6. verifyEmail redirect sudah pakai ?verified=1 yang benar
 * ═══════════════════════════════════════════════════════════════
 */

const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto     = require('crypto');
const path       = require('path');
const { createClient } = require('@supabase/supabase-js');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Supabase Config ──────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://wmsjtknmbqfegqbvxncq.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Indtc2p0a25tYnFmZWdxYnZ4bmNxIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3ODQ3MjQ1MCwiZXhwIjoyMDk0MDQ4NDUwfQ.36cNZ5XLhfDPSvuuzXsSLcFODUAiPyVjgUcOihOfxdo';
const supabase     = createClient(SUPABASE_URL, SUPABASE_KEY);

// ── App Config ───────────────────────────────────────────────────
const CONFIG = {
    JWT_SECRET      : process.env.JWT_SECRET || 'billsmart-super-secret-jwt-2024-ganti-di-produksi',
    JWT_EXPIRES     : '7d',
    BCRYPT_ROUNDS   : 12,
    VERIFY_EXPIRES_H: 24,
    RESET_EXPIRES_H : 1,

    // ✅ FIX #1: SMTP — pastikan EMAIL_FROM sama dengan akun Gmail pengirim
    // Gmail SMTP menolak jika FROM berbeda dari akun yang login
    EMAIL: {
        host  : process.env.SMTP_HOST || 'smtp.gmail.com',
        port  : parseInt(process.env.SMTP_PORT) || 587,
        secure: false, // false = STARTTLS, true = SSL port 465
        auth  : {
            user: process.env.SMTP_USER || 'hamzahhar990@gmail.com',
            pass: process.env.SMTP_PASS || 'khyy ejrz kdun nnsx',  // App Password Gmail (16 char)
        },
        tls: {
            rejectUnauthorized: false  // ✅ FIX: hindari error TLS di beberapa environment
        }
    },
    // ✅ FIX #2: EMAIL_FROM HARUS sama persis dengan SMTP_USER untuk Gmail
    // Gmail menolak kirim dari address yang berbeda dengan login account
    get EMAIL_FROM() {
        const user = process.env.SMTP_USER || 'hamzahhar990@gmail.com';
        return process.env.EMAIL_FROM || `"Billsmart.id" <${user}>`;
    },
    // ✅ FIX #3: APP_URL tidak lagi hardcode — diambil dari request (lihat getAppUrl helper)
    APP_URL: process.env.APP_URL || null,
};

// Helper untuk mendapatkan base URL dari request secara otomatis
// Prioritas: env APP_URL → x-forwarded headers (reverse proxy/ngrok) → request host
function getAppUrl(req) {
    // Jika APP_URL di-set di environment, gunakan itu (untuk production/ngrok)
    if (CONFIG.APP_URL) return CONFIG.APP_URL.replace(/\/$/, '');

    // Cek apakah ada reverse proxy / ngrok headers
    const forwProto = req.headers['x-forwarded-proto'];
    const forwHost  = req.headers['x-forwarded-host'];

    if (forwProto && forwHost) {
        // Ambil proto pertama jika ada beberapa (e.g. "https,http")
        const proto = forwProto.split(',')[0].trim();
        const host  = forwHost.split(',')[0].trim();
        return `${proto}://${host}`;
    }

    // Fallback ke host dari request
    const proto = req.protocol || 'http';
    const host  = req.headers.host || `localhost:${PORT}`;
    return `${proto}://${host}`;
}

// ── Middleware ───────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
app.use(express.static(__dirname));
app.get('/', (req, res) => res.redirect('/login.html'));

// ── Email Transporter ────────────────────────────────────────────
const transporter = nodemailer.createTransport(CONFIG.EMAIL);

// ✅ FIX #4: Verifikasi koneksi SMTP saat startup, bukan saat kirim (tahu langsung jika config salah)
transporter.verify((err) => {
    if (err) {
        console.error('❌ SMTP CONFIG ERROR:', err.message);
        console.error('   → Pastikan App Password Gmail sudah benar dan "Less secure app" atau App Password aktif');
        console.error('   → Cara buat App Password Gmail: myaccount.google.com → Security → App passwords');
    } else {
        console.log('✅ SMTP Terhubung — Email siap dikirim dari', CONFIG.EMAIL.auth.user);
    }
});

async function sendEmail(to, subject, html) {
    try {
        const info = await transporter.sendMail({
            from: CONFIG.EMAIL_FROM,
            to,
            subject,
            html,
        });
        console.log(`✅ Email terkirim ke ${to} — MessageID: ${info.messageId}`);
        return true;
    } catch (e) {
        // ✅ FIX #5: Log error SMTP lebih detail
        console.error('❌ SMTP SEND ERROR:');
        console.error('   Code   :', e.code);
        console.error('   Message:', e.message);
        if (e.code === 'EAUTH') {
            console.error('   → Periksa Gmail App Password! Pastikan 2FA aktif dan App Password dibuat.');
            console.error('   → Link: https://myaccount.google.com/apppasswords');
        }
        if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT') {
            console.error('   → Server tidak bisa mencapai smtp.gmail.com:587. Periksa firewall/network.');
        }
        return false;
    }
}

function emailVerifyTemplate(name, link) {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
    body{font-family:'Segoe UI',sans-serif;background:#080810;color:#f0ede8;margin:0;padding:20px}
    .wrap{max-width:560px;margin:0 auto;background:#13131c;border-radius:16px;overflow:hidden;border:1px solid rgba(201,168,76,.2)}
    .header{background:linear-gradient(135deg,#1a1a24,#13131c);padding:32px;text-align:center;border-bottom:1px solid rgba(201,168,76,.15)}
    .logo{font-size:26px;font-weight:700;color:#c9a84c;letter-spacing:1px}
    .sub{color:#7a7580;font-size:13px;margin-top:4px}
    .body{padding:32px}
    h2{color:#f0ede8;margin:0 0 12px;font-size:22px}
    p{color:#9a96a8;line-height:1.7;margin:0 0 20px;font-size:14px}
    .btn{display:inline-block;background:linear-gradient(135deg,#c9a84c,#b8860b);color:#0a0a0f!important;padding:14px 36px;border-radius:10px;text-decoration:none;font-weight:700;font-size:15px;letter-spacing:.5px}
    .link-box{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:8px;padding:12px 16px;font-size:12px;color:#7a7580;word-break:break-all;margin-top:20px}
    .footer{padding:20px 32px;border-top:1px solid rgba(255,255,255,.05);text-align:center;font-size:12px;color:#555}
    </style></head><body>
    <div class="wrap">
    <div class="header"><div class="logo">Billsmart.id</div><div class="sub">Sistem Kasir Digital Premium</div></div>
    <div class="body">
    <h2>Halo, ${name}! 👋</h2>
    <p>Terima kasih telah mendaftar di <strong style="color:#c9a84c">Billsmart.id</strong>. Satu langkah lagi — verifikasi email Anda untuk mengaktifkan akun.</p>
    <div style="text-align:center;margin:28px 0"><a href="${link}" class="btn">✅ Verifikasi Email Saya</a></div>
    <p style="font-size:13px">Link ini berlaku selama <strong style="color:#f0ede8">24 jam</strong>. Jika Anda tidak mendaftar, abaikan email ini.</p>
    <div class="link-box">Atau salin link ini ke browser:<br><br>${link}</div>
    </div>
    <div class="footer">© 2025 Billsmart.id · Sistem Kasir Digital · Indonesia</div>
    </div></body></html>`;
}

function emailResetTemplate(name, link) {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
    body{font-family:'Segoe UI',sans-serif;background:#080810;color:#f0ede8;margin:0;padding:20px}
    .wrap{max-width:560px;margin:0 auto;background:#13131c;border-radius:16px;overflow:hidden;border:1px solid rgba(201,168,76,.2)}
    .header{background:linear-gradient(135deg,#1a1a24,#13131c);padding:32px;text-align:center;border-bottom:1px solid rgba(201,168,76,.15)}
    .logo{font-size:26px;font-weight:700;color:#c9a84c}
    .body{padding:32px}
    h2{color:#f0ede8;margin:0 0 12px}
    p{color:#9a96a8;line-height:1.7;margin:0 0 20px;font-size:14px}
    .btn{display:inline-block;background:linear-gradient(135deg,#c9a84c,#b8860b);color:#0a0a0f!important;padding:14px 36px;border-radius:10px;text-decoration:none;font-weight:700;font-size:15px}
    .footer{padding:20px 32px;border-top:1px solid rgba(255,255,255,.05);text-align:center;font-size:12px;color:#555}
    </style></head><body>
    <div class="wrap">
    <div class="header"><div class="logo">Billsmart.id</div></div>
    <div class="body">
    <h2>Reset Password 🔐</h2>
    <p>Halo <strong style="color:#f0ede8">${name}</strong>, kami menerima permintaan reset password untuk akun Anda di Billsmart.id.</p>
    <div style="text-align:center;margin:28px 0"><a href="${link}" class="btn">Reset Password Sekarang</a></div>
    <p style="font-size:13px">Link berlaku <strong style="color:#f0ede8">1 jam</strong>. Jika Anda tidak meminta reset, abaikan email ini — password Anda tetap aman.</p>
    </div>
    <div class="footer">© 2025 Billsmart.id</div>
    </div></body></html>`;
}

// ── Auth Middleware ───────────────────────────────────────────────
function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token tidak ditemukan.' });
    try {
        req.user = jwt.verify(token, CONFIG.JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Token tidak valid atau kadaluarsa.' });
    }
}

// ── Helpers ───────────────────────────────────────────────────────
function generateToken() { return crypto.randomBytes(48).toString('hex'); }
function addHours(h)     { return new Date(Date.now() + h * 3600000).toISOString(); }

// ── DATABASE SCHEMA (jalankan sekali di Supabase SQL Editor) ─────
/*
CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    email       TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    role        TEXT DEFAULT 'kasir',
    is_verified BOOLEAN DEFAULT FALSE,
    photo_url   TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token      TEXT NOT NULL UNIQUE,
    type       TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used       BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS menu_items (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category    TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    price       INTEGER NOT NULL,
    stock       INTEGER DEFAULT 0,
    image_url   TEXT,
    badge       TEXT,
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS transactions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_no      TEXT UNIQUE NOT NULL,
    cashier_id      UUID,
    cashier_name    TEXT,
    items_json      JSONB NOT NULL,
    subtotal        INTEGER NOT NULL,
    tax             INTEGER DEFAULT 0,
    discount        INTEGER DEFAULT 0,
    total           INTEGER NOT NULL,
    payment_method  TEXT DEFAULT 'tunai',
    payment_amount  INTEGER DEFAULT 0,
    change_amount   INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'selesai',
    note            TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_tokens_token ON email_tokens(token);
CREATE INDEX IF NOT EXISTS idx_tx_created ON transactions(created_at);
*/

// ── SEED MENU ─────────────────────────────────────────────────────
async function seedMenuIfEmpty() {
    const { count } = await supabase.from('menu_items').select('*', { count: 'exact', head: true });
    if (count === 0) {
        await supabase.from('menu_items').insert([
            { category:'Makanan',  name:'Wagyu Steak',        description:'Premium wagyu beef 200gr', price:750000, stock:15, badge:'Terlaris' },
            { category:'Makanan',  name:'Lobster Bakar',       description:'Lobster segar 500gr',      price:650000, stock:5,  badge:'Promo'    },
            { category:'Makanan',  name:'Nasi Goreng Spesial', description:'Dengan telur & ayam',      price:45000,  stock:50, badge:null       },
            { category:'Makanan',  name:'Mie Goreng',          description:'Level pedas 1-5',          price:35000,  stock:50, badge:null       },
            { category:'Minuman',  name:'Es Teh Manis',        description:'Teh segar manis dingin',   price:15000,  stock:100,badge:null       },
            { category:'Minuman',  name:'Kopi Susu',           description:'Creamy latte arabika',     price:35000,  stock:80, badge:null       },
            { category:'Minuman',  name:'Jus Alpukat',         description:'Alpukat segar + susu',     price:28000,  stock:30, badge:null       },
            { category:'Dessert',  name:'Es Krim Vanilla',     description:'Double scoop',             price:25000,  stock:20, badge:null       },
        ]);
        console.log('✅ Menu seed berhasil ditambahkan');
    }
}
seedMenuIfEmpty().catch(console.error);

// ══════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
        return res.status(400).json({ error: 'Semua field wajib diisi.' });
    if (password.length < 8)
        return res.status(400).json({ error: 'Password minimal 8 karakter.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.status(400).json({ error: 'Format email tidak valid.' });

    const cleanEmail = email.toLowerCase().trim();

    const { data: existing } = await supabase
        .from('users').select('id').eq('email', cleanEmail).maybeSingle();
    if (existing)
        return res.status(409).json({ error: 'Email sudah terdaftar. Silakan masuk.' });

    const hashed = await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS);
    const { data: newUser, error: insertErr } = await supabase
        .from('users')
        .insert({ name: name.trim(), email: cleanEmail, password: hashed })
        .select('id, name, email').single();

    if (insertErr)
        return res.status(500).json({ error: 'Gagal membuat akun. Coba lagi.' });

    // Token verifikasi
    const token = generateToken();
    await supabase.from('email_tokens').insert({
        user_id: newUser.id, token, type: 'verify',
        expires_at: addHours(CONFIG.VERIFY_EXPIRES_H)
    });

    // ✅ FIX #6: gunakan getAppUrl(req) bukan hardcode CONFIG.APP_URL
    const appUrl     = getAppUrl(req);
    const verifyLink = `${appUrl}/api/auth/verify-email?token=${token}`;

    console.log(`📧 Mengirim email verifikasi ke ${cleanEmail}...`);
    console.log(`   Link: ${verifyLink}`);

    const sent = await sendEmail(
        cleanEmail,
        '✅ Verifikasi Email Anda — Billsmart.id',
        emailVerifyTemplate(name, verifyLink)
    );

    if (!sent) {
        // ✅ FIX #7: Jangan hapus user jika email gagal — biarkan user coba resend
        // Sebelumnya user dihapus sehingga tidak bisa login atau resend
        return res.status(500).json({
            error: 'Akun berhasil dibuat, tapi email verifikasi gagal dikirim. ' +
                   'Cek konfigurasi SMTP di server (lihat console), atau gunakan fitur "Kirim Ulang Email".',
            canResend: true,
            email: cleanEmail
        });
    }

    res.json({ success: true, message: `Email verifikasi dikirim ke ${cleanEmail}. Cek inbox & folder spam Anda!` });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: 'Email dan password wajib diisi.' });

    const { data: user } = await supabase
        .from('users').select('*').eq('email', email.toLowerCase().trim()).maybeSingle();
    if (!user)
        return res.status(401).json({ error: 'Email tidak terdaftar.' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
        return res.status(401).json({ error: 'Password salah.' });

    if (!user.is_verified)
        return res.status(403).json({
            error: 'Email belum diverifikasi. Cek inbox Anda.',
            code: 'NOT_VERIFIED',
            email: user.email
        });

    const token = jwt.sign(
        { id: user.id, email: user.email, name: user.name, role: user.role },
        CONFIG.JWT_SECRET,
        { expiresIn: CONFIG.JWT_EXPIRES }
    );

    res.json({
        success: true, token,
        user: { id: user.id, name: user.name, email: user.email, role: user.role, photoUrl: user.photo_url }
    });
});

// GET /api/auth/verify-email?token=xxx
app.get('/api/auth/verify-email', async (req, res) => {
    const { token } = req.query;
    if (!token) {
        console.warn('⚠️  verify-email: token query param kosong');
        return res.redirect('/login.html?error=token_missing');
    }

    console.log(`🔍 verify-email: mencari token ${token.slice(0,12)}...`);

    const { data: record, error: qErr } = await supabase
        .from('email_tokens')
        .select('*')
        .eq('token', token)
        .eq('type', 'verify')
        .eq('used', false)
        .gt('expires_at', new Date().toISOString())
        .maybeSingle();

    if (qErr) {
        console.error('❌ verify-email DB error:', qErr.message);
        return res.redirect('/login.html?error=server_error');
    }

    if (!record) {
        // Cek apakah token ada tapi sudah dipakai (berarti sudah verified)
        const { data: usedRecord } = await supabase
            .from('email_tokens')
            .select('used, user_id')
            .eq('token', token)
            .eq('type', 'verify')
            .maybeSingle();

        if (usedRecord && usedRecord.used) {
            console.log('ℹ️  verify-email: token sudah dipakai sebelumnya → redirect verified=1');
            return res.redirect('/login.html?verified=1');
        }

        console.warn('⚠️  verify-email: token tidak ditemukan atau kadaluarsa');
        return res.redirect('/login.html?error=token_invalid');
    }

    // Update user is_verified
    const { error: updateErr } = await supabase
        .from('users')
        .update({ is_verified: true, updated_at: new Date().toISOString() })
        .eq('id', record.user_id);

    if (updateErr) {
        console.error('❌ verify-email: gagal update user:', updateErr.message);
        return res.redirect('/login.html?error=server_error');
    }

    await supabase.from('email_tokens').update({ used: true }).eq('id', record.id);

    console.log(`✅ verify-email: user ${record.user_id} berhasil diverifikasi`);
    res.redirect('/login.html?verified=1');
});

// GET /api/auth/check-verified?email=xxx  (dipakai login.html untuk polling)
app.get('/api/auth/check-verified', async (req, res) => {
    const email = req.query.email?.toLowerCase().trim();
    if (!email) return res.status(400).json({ error: 'Email wajib diisi.' });
    const { data: user } = await supabase
        .from('users').select('is_verified').eq('email', email).maybeSingle();
    if (!user) return res.status(404).json({ error: 'Email tidak terdaftar.' });
    res.json({ is_verified: user.is_verified });
});


app.post('/api/auth/resend-verification', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email wajib diisi.' });

    const { data: user } = await supabase
        .from('users').select('*').eq('email', email.toLowerCase()).maybeSingle();
    if (!user) return res.status(404).json({ error: 'Email tidak terdaftar.' });
    if (user.is_verified) return res.status(400).json({ error: 'Email sudah terverifikasi. Silakan login.' });

    // Rate limit 60 detik
    const sixtySecsAgo = new Date(Date.now() - 60000).toISOString();
    const { data: recent } = await supabase
        .from('email_tokens')
        .select('id').eq('user_id', user.id).eq('type', 'verify')
        .gt('created_at', sixtySecsAgo).maybeSingle();
    if (recent) return res.status(429).json({ error: 'Tunggu 60 detik sebelum mengirim ulang.' });

    // Hapus token lama
    await supabase.from('email_tokens').delete().eq('user_id', user.id).eq('type', 'verify');

    const token = generateToken();
    await supabase.from('email_tokens').insert({
        user_id: user.id, token, type: 'verify',
        expires_at: addHours(CONFIG.VERIFY_EXPIRES_H)
    });

    const appUrl     = getAppUrl(req);
    const verifyLink = `${appUrl}/api/auth/verify-email?token=${token}`;
    const sent = await sendEmail(email, '✅ Verifikasi Email — Billsmart.id', emailVerifyTemplate(user.name, verifyLink));

    if (!sent) return res.status(500).json({ error: 'Gagal mengirim email. Periksa konfigurasi SMTP.' });
    res.json({ success: true, message: 'Email verifikasi dikirim ulang. Cek inbox & folder spam.' });
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email wajib diisi.' });

    const { data: user } = await supabase
        .from('users').select('*').eq('email', email.toLowerCase()).maybeSingle();

    // Selalu return success untuk keamanan (tidak reveal apakah email terdaftar)
    if (!user) return res.json({ success: true, message: 'Jika email terdaftar, link reset dikirim. Cek inbox & spam.' });

    await supabase.from('email_tokens').delete().eq('user_id', user.id).eq('type', 'reset');

    const token = generateToken();
    await supabase.from('email_tokens').insert({
        user_id: user.id, token, type: 'reset',
        expires_at: addHours(CONFIG.RESET_EXPIRES_H)
    });

    const appUrl    = getAppUrl(req);
    const resetLink = `${appUrl}/reset-password.html?token=${token}`;
    await sendEmail(email, '🔐 Reset Password — Billsmart.id', emailResetTemplate(user.name, resetLink));

    res.json({ success: true, message: 'Jika email terdaftar, link reset dikirim. Cek inbox & spam Anda.' });
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token dan password wajib diisi.' });
    if (password.length < 8) return res.status(400).json({ error: 'Password minimal 8 karakter.' });

    const { data: record } = await supabase
        .from('email_tokens')
        .select('*').eq('token', token).eq('type', 'reset').eq('used', false)
        .gt('expires_at', new Date().toISOString())
        .maybeSingle();

    if (!record) return res.status(400).json({ error: 'Link reset tidak valid atau sudah kadaluarsa.' });

    const hashed = await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS);
    await supabase.from('users')
        .update({ password: hashed, updated_at: new Date().toISOString() })
        .eq('id', record.user_id);
    await supabase.from('email_tokens').update({ used: true }).eq('id', record.id);

    res.json({ success: true, message: 'Password berhasil direset. Silakan masuk.' });
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, async (req, res) => {
    const { data: user } = await supabase
        .from('users')
        .select('id, name, email, role, is_verified, photo_url, created_at')
        .eq('id', req.user.id).maybeSingle();
    if (!user) return res.status(404).json({ error: 'User tidak ditemukan.' });
    res.json({ user });
});

// ══════════════════════════════════════════════════════════════════
//  MENU ROUTES
// ══════════════════════════════════════════════════════════════════

app.get('/api/menu', authMiddleware, async (req, res) => {
    const { data: items } = await supabase
        .from('menu_items').select('*').eq('is_active', true).order('category').order('name');
    res.json({ items: items || [] });
});

// ✅ FIX #9: Endpoint tambah menu (dipanggil dari dashboard button "Tambah Menu")
app.post('/api/menu', authMiddleware, async (req, res) => {
    const { category, name, description, price, stock, image_url, badge } = req.body;
    if (!category || !name || price === undefined)
        return res.status(400).json({ error: 'Category, name, dan price wajib diisi.' });
    if (isNaN(price) || price < 0)
        return res.status(400).json({ error: 'Harga tidak valid.' });

    const { data, error } = await supabase.from('menu_items')
        .insert({ category, name, description: description || '', price: parseInt(price), stock: parseInt(stock) || 0, image_url: image_url || null, badge: badge || null })
        .select('id, name, price, stock').single();

    if (error) {
        console.error('Menu insert error:', error);
        return res.status(500).json({ error: 'Gagal menambah menu.' });
    }
    res.json({ success: true, id: data.id, message: `Menu "${data.name}" berhasil ditambahkan.` });
});

app.put('/api/menu/:id', authMiddleware, async (req, res) => {
    const { category, name, description, price, stock, image_url, badge, is_active } = req.body;
    const { error } = await supabase.from('menu_items')
        .update({
            category, name, description, price, stock, image_url, badge,
            is_active: is_active !== undefined ? is_active : true
        })
        .eq('id', req.params.id);

    if (error) return res.status(500).json({ error: 'Gagal update menu.' });
    res.json({ success: true });
});

// ✅ FIX #10: Endpoint restock (patch stok saja)
app.patch('/api/menu/:id/stock', authMiddleware, async (req, res) => {
    const { stock, add } = req.body; // stock = set langsung, add = tambah ke stok existing

    if (add !== undefined) {
        // Tambahkan ke stok existing
        const { data: item } = await supabase.from('menu_items').select('stock').eq('id', req.params.id).single();
        if (!item) return res.status(404).json({ error: 'Menu tidak ditemukan.' });
        const newStock = Math.max(0, (item.stock || 0) + parseInt(add));
        await supabase.from('menu_items').update({ stock: newStock }).eq('id', req.params.id);
        return res.json({ success: true, stock: newStock });
    }

    if (stock !== undefined) {
        if (isNaN(stock) || stock < 0) return res.status(400).json({ error: 'Stok tidak valid.' });
        await supabase.from('menu_items').update({ stock: parseInt(stock) }).eq('id', req.params.id);
        return res.json({ success: true, stock: parseInt(stock) });
    }

    res.status(400).json({ error: 'Sediakan "stock" atau "add" di request body.' });
});

app.delete('/api/menu/:id', authMiddleware, async (req, res) => {
    await supabase.from('menu_items').update({ is_active: false }).eq('id', req.params.id);
    res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════════
//  TRANSACTION ROUTES
// ══════════════════════════════════════════════════════════════════

app.get('/api/transactions', authMiddleware, async (req, res) => {
    const { limit = 50, offset = 0, date } = req.query;
    let query = supabase.from('transactions').select('*', { count: 'exact' });
    if (date) query = query.gte('created_at', date + 'T00:00:00').lte('created_at', date + 'T23:59:59');
    query = query.order('created_at', { ascending: false })
                 .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);
    const { data: transactions, count } = await query;
    res.json({ transactions: transactions || [], total: count });
});

app.post('/api/transactions', authMiddleware, async (req, res) => {
    const { items, subtotal, tax, discount, total, payment_method, payment_amount, change_amount, note } = req.body;
    if (!items || !total) return res.status(400).json({ error: 'Data transaksi tidak lengkap.' });

    const itemsArr = typeof items === 'string' ? JSON.parse(items) : items;
    const invNo    = 'INV-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6).toUpperCase();
    const { data: user } = await supabase.from('users').select('name').eq('id', req.user.id).maybeSingle();

    // Update stok
    for (const item of itemsArr) {
        const { data: menuItem } = await supabase.from('menu_items').select('stock').eq('id', item.id).single();
        if (!menuItem || menuItem.stock < item.qty)
            return res.status(400).json({ error: `Stok ${item.name} tidak cukup.` });
        await supabase.from('menu_items').update({ stock: menuItem.stock - item.qty }).eq('id', item.id);
    }

    const { error } = await supabase.from('transactions').insert({
        invoice_no: invNo, cashier_id: req.user.id, cashier_name: user?.name || req.user.email,
        items_json: itemsArr, subtotal: subtotal || 0, tax: tax || 0, discount: discount || 0,
        total, payment_method: payment_method || 'tunai', payment_amount: payment_amount || 0,
        change_amount: change_amount || 0, note: note || ''
    });

    if (error) return res.status(500).json({ error: 'Gagal menyimpan transaksi.' });
    res.json({ success: true, invoice_no: invNo });
});

// ── Dashboard Summary ─────────────────────────────────────────────
app.get('/api/dashboard/summary', authMiddleware, async (req, res) => {
    const today      = new Date().toISOString().split('T')[0];
    const monthStart = today.slice(0, 7) + '-01';

    const { data: todayTx } = await supabase.from('transactions')
        .select('total').eq('status', 'selesai')
        .gte('created_at', today + 'T00:00:00').lte('created_at', today + 'T23:59:59');

    const { data: monthTx } = await supabase.from('transactions')
        .select('total').eq('status', 'selesai').gte('created_at', monthStart + 'T00:00:00');

    const { data: lowStock } = await supabase.from('menu_items')
        .select('name, stock').eq('is_active', true).lte('stock', 10).order('stock');

    const { data: allItems } = await supabase.from('menu_items')
        .select('id, name, price').eq('is_active', true).limit(20);

    const todayTotal = (todayTx || []).reduce((s, t) => s + t.total, 0);
    const monthTotal = (monthTx || []).reduce((s, t) => s + t.total, 0);

    res.json({
        today   : { total: todayTotal, count: (todayTx || []).length },
        month   : { total: monthTotal, count: (monthTx || []).length },
        lowStock: lowStock || [],
        menuCount: (allItems || []).length,
    });
});

// ✅ FIX #11: Endpoint export laporan (dipanggil dari "Cetak Laporan")
app.get('/api/report/export', authMiddleware, async (req, res) => {
    const { type = 'daily', date } = req.query;
    const today = date || new Date().toISOString().split('T')[0];
    const monthStart = today.slice(0, 7) + '-01';

    let txQuery = supabase.from('transactions').select('*').order('created_at', { ascending: false });

    if (type === 'daily') {
        txQuery = txQuery.gte('created_at', today + 'T00:00:00').lte('created_at', today + 'T23:59:59');
    } else if (type === 'monthly') {
        txQuery = txQuery.gte('created_at', monthStart + 'T00:00:00');
    }

    const { data: transactions } = await txQuery;
    const txs = transactions || [];
    const totalRevenue = txs.reduce((s, t) => s + t.total, 0);

    // Generate HTML report
    const reportHtml = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Laporan ${type === 'daily' ? 'Harian' : 'Bulanan'} — Billsmart.id</title>
<style>
body{font-family:sans-serif;color:#222;max-width:800px;margin:0 auto;padding:20px}
h1{color:#b8860b;margin-bottom:4px}
.sub{color:#888;font-size:13px;margin-bottom:20px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#f5f0e8;color:#555;text-align:left;padding:8px 10px;border-bottom:2px solid #e0d5b8}
td{padding:7px 10px;border-bottom:1px solid #eee}
.total-row td{font-weight:700;background:#fffdf5;border-top:2px solid #e0d5b8}
.summary{display:flex;gap:20px;margin-bottom:20px}
.sum-box{border:1px solid #e0d5b8;border-radius:8px;padding:14px 20px;flex:1}
.sum-label{font-size:12px;color:#888;text-transform:uppercase;letter-spacing:1px}
.sum-val{font-size:22px;font-weight:700;color:#b8860b;margin-top:4px}
</style></head><body>
<h1>Billsmart.id — Laporan ${type === 'daily' ? 'Harian' : 'Bulanan'}</h1>
<div class="sub">Periode: ${type === 'daily' ? today : today.slice(0,7)} · Dicetak: ${new Date().toLocaleString('id-ID')}</div>
<div class="summary">
<div class="sum-box"><div class="sum-label">Total Pendapatan</div><div class="sum-val">Rp ${totalRevenue.toLocaleString('id-ID')}</div></div>
<div class="sum-box"><div class="sum-label">Jumlah Transaksi</div><div class="sum-val">${txs.length}</div></div>
<div class="sum-box"><div class="sum-label">Rata-rata per Transaksi</div><div class="sum-val">Rp ${txs.length ? Math.round(totalRevenue/txs.length).toLocaleString('id-ID') : 0}</div></div>
</div>
<table>
<thead><tr><th>#</th><th>Invoice</th><th>Waktu</th><th>Kasir</th><th>Metode</th><th>Total</th></tr></thead>
<tbody>
${txs.map((t,i) => `<tr>
<td>${i+1}</td><td>${t.invoice_no}</td>
<td>${new Date(t.created_at).toLocaleString('id-ID')}</td>
<td>${t.cashier_name||'-'}</td><td>${t.payment_method||'tunai'}</td>
<td>Rp ${t.total.toLocaleString('id-ID')}</td></tr>`).join('')}
${txs.length === 0 ? '<tr><td colspan="6" style="text-align:center;color:#aaa;padding:20px">Tidak ada transaksi</td></tr>' : ''}
</tbody>
<tfoot><tr class="total-row"><td colspan="5">TOTAL</td><td>Rp ${totalRevenue.toLocaleString('id-ID')}</td></tr></tfoot>
</table>
<div style="margin-top:30px;text-align:center;font-size:11px;color:#bbb">© 2025 Billsmart.id · Laporan ini dibuat otomatis oleh sistem</div>
</body></html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(reportHtml);
});

// ── Start Server ──────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════╗
║   🏪  Billsmart.id Backend Server v3.1         ║
║   Running on http://localhost:${PORT}              ║
║   Database: Supabase PostgreSQL                ║
╚════════════════════════════════════════════════╝

📋 CHECKLIST PENTING:
   ✅ SUPABASE_KEY = Service Role Key (bukan anon key)
   ✅ SMTP_USER    = hamzahhar990@gmail.com
   ✅ SMTP_PASS    = App Password 16 karakter (bukan password Gmail biasa)
      → Cara buat: myaccount.google.com → Security → App passwords
   ✅ APP_URL      = otomatis detect dari request (tidak perlu di-set)
      → Atau set env APP_URL=https://domain-anda.com untuk produksi
    `);
});

module.exports = app;
