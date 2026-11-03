const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'owner';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DB_FILE = path.join(DATA_DIR, 'db.json');
const DATABASE_URL = process.env.DATABASE_URL;

let pgPool = null;
if (DATABASE_URL) {
  try {
    const { Pool } = require('pg');
    pgPool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    initPostgres();
  } catch (err) {
    console.warn('PostgreSQL failed to initialize, falling back to local file:', err.message);
  }
}

// In-memory data store structure
let DB = {
  students: [],
  subjects: [],
  teachers: [],
  attendance: [],
  marks: []
};

// Sessions and login rate limiter
const sessions = new Map(); // token -> { role, me, admin }
const loginAttempts = new Map(); // ip -> { count, resetAt }

// --- Storage Handlers ---
async function initPostgres() {
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS sms_store (
      key TEXT PRIMARY KEY,
      data JSONB NOT NULL
    );
  `);
  const res = await pgPool.query('SELECT data FROM sms_store WHERE key = $1', ['app_data']);
  if (res.rows.length) {
    DB = res.rows[0].data;
  } else {
    await saveStore();
  }
}

function loadStore() {
  if (pgPool) return;
  try {
    if (fs.existsSync(DB_FILE)) {
      DB = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } else {
      saveStore();
    }
  } catch (e) {
    console.error('Error loading db.json:', e);
  }
}

async function saveStore() {
  if (pgPool) {
    await pgPool.query(
      `INSERT INTO sms_store (key, data) VALUES ('app_data', $1)
       ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data`,
      [JSON.stringify(DB)]
    );
  } else {
    fs.writeFileSync(DB_FILE, JSON.stringify(DB, null, 2), 'utf8');
  }
}

// --- Security Helpers ---
function hashPassword(pass, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(pass, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(pass, stored) {
  if (!stored) return false;
  const [salt, key] = stored.split(':');
  if (!salt || !key) return false;
  const hashed = crypto.scryptSync(pass, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(key, 'hex'), Buffer.from(hashed, 'hex'));
}

function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(';').forEach(c => {
      const parts = c.split('=');
      list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
  }
  return list;
}

function checkRateLimit(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip) || { count: 0, resetAt: now + 60000 };
  if (now > rec.resetAt) {
    rec.count = 1;
    rec.resetAt = now + 60000;
  } else {
    rec.count++;
  }
  loginAttempts.set(ip, rec);
  return rec.count <= 10; // max 10 login attempts per minute
}

// --- Request Helpers ---
function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function getBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1e6) {
        req.socket.destroy();
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(new Error('Invalid JSON'));
      }
    });
  });
}

// --- HTTP Server ---
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  const method = req.method;

  // Session check
  const cookies = parseCookies(req);
  const sessionToken = cookies.session;
  const session = sessions.get(sessionToken);

  // 1. Static Files
  if (pathname === '/' || pathname === '/index.html') {
    const file = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(file)) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return fs.createReadStream(file).pipe(res);
    }
  }

  // 2. Authentication: Login
  if (pathname === '/api/login' && method === 'POST') {
    const ip = req.socket.remoteAddress;
    if (!checkRateLimit(ip)) {
      return sendJson(res, 429, { error: 'Too many attempts. Please try again later.' });
    }

    try {
      const { role, user, pass } = await getBody(req);
      if (!user || !pass) return sendJson(res, 400, { error: 'Username and password required' });

      // Admin Login
      if (role === 'a') {
        if (user.toLowerCase() === ADMIN_USER.toLowerCase() && pass === ADMIN_PASS) {
          const token = crypto.randomBytes(32).toString('hex');
          sessions.set(token, { role: 't', me: 'admin', admin: true });
          res.setHeader('Set-Cookie', `session=${token}; HttpOnly; Path=/; SameSite=Strict`);
          return sendJson(res, 200, { ok: true });
        }
        return sendJson(res, 401, { error: 'Invalid credentials' });
      }

      // Teacher Login
      if (role === 't') {
        const teacher = DB.teachers.find(t => t.user.toLowerCase() === user.toLowerCase());
        if (teacher && verifyPassword(pass, teacher.pass)) {
          const token = crypto.randomBytes(32).toString('hex');
          sessions.set(token, { role: 't', me: teacher.id, admin: false });
          res.setHeader('Set-Cookie', `session=${token}; HttpOnly; Path=/; SameSite=Strict`);
          return sendJson(res, 200, { ok: true });
        }
        return sendJson(res, 401, { error: 'Invalid username or password' });
      }

      // Student Login
      if (role === 's') {
        const student = DB.students.find(s => s.user.toLowerCase() === user.toLowerCase());
        if (student && verifyPassword(pass, student.pass)) {
          const token = crypto.randomBytes(32).toString('hex');
          sessions.set(token, { role: 's', me: student.id, admin: false });
          res.setHeader('Set-Cookie', `session=${token}; HttpOnly; Path=/; SameSite=Strict`);
          return sendJson(res, 200, { ok: true });
        }
        return sendJson(res, 401, { error: 'Invalid username or password' });
      }

      return sendJson(res, 400, { error: 'Invalid role' });
    } catch (e) {
      return sendJson(res, 400, { error: e.message });
    }
  }

  // 3. Authentication: Logout
  if (pathname === '/api/logout' && method === 'POST') {
    if (sessionToken) sessions.delete(sessionToken);
    res.setHeader('Set-Cookie', 'session=; HttpOnly; Path=/; Max-Age=0');
    return sendJson(res, 200, { ok: true });
  }

  // Protected API routes below
  if (!session) {
    if (pathname === '/api/data') return sendJson(res, 200, { role: null, data: DB });
    return sendJson(res, 401, { error: 'Unauthorized' });
  }

  // 4. GET /api/data
  if (pathname === '/api/data' && method === 'GET') {
    // Student data filtering
    if (session.role === 's') {
      const myId = session.me;
      return sendJson(res, 200, {
        role: 's',
        me: myId,
        admin: false,
        data: {
          students: DB.students.filter(s => s.id === myId).map(({ pass, ...rest }) => rest),
          subjects: DB.subjects,
          attendance: DB.attendance.map(a => ({ id: a.id, sub: a.sub, date: a.date, m: { [myId]: a.m?.[myId] } })),
          marks: DB.marks.filter(m => m.stu === myId),
          teachers: []
        }
      });
    }

    // Teacher or Admin data filtering
    return sendJson(res, 200, {
      role: 't',
      me: session.me,
      admin: session.admin,
      data: {
        students: DB.students.map(({ pass, ...rest }) => rest),
        subjects: DB.subjects,
        attendance: DB.attendance,
        marks: DB.marks,
        teachers: DB.teachers.map(({ pass, ...rest }) => rest)
      }
    });
  }

  // 5. REST Collections: PUT /api/:collection/:id & DELETE /api/:collection/:id
  const match = pathname.match(/^\/api\/([a-z]+)\/([^/]+)$/);
  if (match) {
    const [, col, id] = match;
    if (!['students', 'subjects', 'teachers', 'attendance', 'marks'].includes(col)) {
      return sendJson(res, 404, { error: 'Unknown resource' });
    }

    // Authorization checks
    if (session.role !== 't') return sendJson(res, 403, { error: 'Permission denied' });
    if ((col === 'subjects' || col === 'teachers') && !session.admin) {
      return sendJson(res, 403, { error: 'Only admins can modify ' + col });
    }

    // Handle PUT (create/update)
    if (method === 'PUT') {
      try {
        const body = await getBody(req);
        body.id = id;

        // Hash passwords for students and teachers if provided
        if ((col === 'students' || col === 'teachers') && body.pass) {
          body.pass = hashPassword(body.pass);
        } else if (col === 'students' || col === 'teachers') {
          // Keep existing password if not updated
          const existing = DB[col].find(x => x.id === id);
          if (existing) body.pass = existing.pass;
        }

        const idx = DB[col].findIndex(x => x.id === id);
        if (idx >= 0) {
          DB[col][idx] = { ...DB[col][idx], ...body };
        } else {
          DB[col].push(body);
        }

        await saveStore();
        return sendJson(res, 200, { ok: true });
      } catch (e) {
        return sendJson(res, 400, { error: e.message });
      }
    }

    // Handle DELETE
    if (method === 'DELETE') {
      DB[col] = DB[col].filter(x => x.id !== id);

      // Cascade deletes for cleanup
      if (col === 'subjects') {
        DB.attendance = DB.attendance.filter(a => a.sub !== id);
        DB.marks = DB.marks.filter(m => m.sub !== id);
      } else if (col === 'students') {
        DB.marks = DB.marks.filter(m => m.stu !== id);
      }

      await saveStore();
      return sendJson(res, 200, { ok: true });
    }
  }

  sendJson(res, 404, { error: 'Not found' });
});

loadStore();
server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
