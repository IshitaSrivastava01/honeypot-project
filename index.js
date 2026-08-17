require('dotenv').config();
const express = require('express');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const fs = require('fs');
const { MongoClient } = require('mongodb');

// ---- MongoDB setup ----
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);
let logsCollection;

async function connectDB() {
  try {
    await client.connect();
    const db = client.db('honeypot'); // database name (auto-created if it doesn't exist)
    logsCollection = db.collection('attacks'); // collection name (auto-created)
    console.log('Connected to MongoDB Atlas');
  } catch (err) {
    console.error('MongoDB connection failed:', err);
  }
}
connectDB();

// Reusable function to log any attack attempt in structured format
function logAttempt(eventType, req, extra = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    ip: req.ip,
    endpoint: req.originalUrl,
    method: req.method,
    userAgent: req.get('User-Agent'),
    eventType: eventType,
    ...extra
  };

  // Keep the file log as a local backup (resets on Render restart, but fine as fallback)
  fs.appendFile('attacks.log', JSON.stringify(entry) + '\n', (err) => {
    if (err) console.error('Failed to write log file:', err);
  });

  // Write to MongoDB (persistent, survives restarts)
  if (logsCollection) {
    logsCollection.insertOne(entry).catch(err => {
      console.error('Failed to write log to MongoDB:', err);
    });
  }

  console.log(entry);
}

// Track login attempts per IP for brute-force detection
const loginAttempts = {};

function isBruteForce(ip) {
  const now = Date.now();
  const windowMs = 30 * 1000;
  const maxAttempts = 3;

  if (!loginAttempts[ip]) {
    loginAttempts[ip] = [];
  }

  loginAttempts[ip] = loginAttempts[ip].filter(ts => now - ts < windowMs);
  loginAttempts[ip].push(now);

  return loginAttempts[ip].length > maxAttempts;
}

// Detect common SQLi and XSS patterns in user input
function detectAttackType(input) {
  const sqliPatterns = [/('|--|;|\bOR\b|\bUNION\b|\bSELECT\b)/i];
  const xssPatterns = [/<script.*?>|javascript:|onerror\s*=|onload\s*=/i];

  if (sqliPatterns.some(pattern => pattern.test(input))) {
    return 'sqli_attempt';
  }
  if (xssPatterns.some(pattern => pattern.test(input))) {
    return 'xss_attempt';
  }
  return 'none';
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Common target for automated scanners/attackers probing for admin panels
app.post('/admin/login', (req, res) => {
  const bruteForce = isBruteForce(req.ip);
  logAttempt('login_attempt', req, {
    username: req.body.username,
    password: req.body.password,
    flagged_brute_force: bruteForce
  });
  res.status(401).json({ error: 'Invalid credentials' });
});

// Fake exposed .env file
app.get('/.env', (req, res) => {
  logAttempt('env_scan', req);
  res.status(404).send('Not Found');
});

// Fake user data endpoint
app.get('/api/users', (req, res) => {
  logAttempt('user_enumeration', req);
  res.status(403).json({ error: 'Forbidden' });
});

// Fake search endpoint — now using SQLi/XSS detection
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  const attackType = detectAttackType(query);
  logAttempt('search_attempt', req, { query: query, detected_attack_type: attackType });
  res.status(200).send('No results found.');
});

// Fake file upload endpoint — attackers often test if they can upload malicious files
app.post('/upload', upload.single('file'), (req, res) => {
  logAttempt('file_upload_attempt', req, {
    filename: req.file ? req.file.originalname : 'unknown',
    mimetype: req.file ? req.file.mimetype : 'unknown',
    size: req.file ? req.file.size : 0
  });
  res.status(500).json({ error: 'Upload failed. Please try again later.' });
});

// Deliberately generic homepage
app.get('/', (req, res) => {
  res.send('Welcome to the portal');
});

app.listen(PORT, () => {
  console.log(`Honeypot running on port ${PORT}`);
});