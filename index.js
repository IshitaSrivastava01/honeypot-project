const express = require('express');
const fs = require('fs');

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

  fs.appendFile('attacks.log', JSON.stringify(entry) + '\n', (err) => {
    if (err) console.error('Failed to write log:', err);
  });

  console.log(entry);
}

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Common target for automated scanners/attackers probing for admin panels
app.post('/admin/login', (req, res) => {
  logAttempt('login_attempt', req, { username: req.body.username, password: req.body.password });
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

// Fake search endpoint
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  logAttempt('search_attempt', req, { query: query });
  res.status(200).send('No results found.');
});

// Deliberately generic homepage
app.get('/', (req, res) => {
  res.send('Welcome to the portal');
});

app.listen(PORT, () => {
  console.log(`Honeypot running on port ${PORT}`);
});