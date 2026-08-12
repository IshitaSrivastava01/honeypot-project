const express = require('express'); 
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Common target for automated scanners/attackers probing for admin panels
app.post('/admin/login', (req, res) => {
    // Log whatever credentials are sent — this is the core purpose of the honeypot
  console.log('Login attempt:', req.body);
  // Respond like a real login failure so the attacker doesn't suspect a trap
  res.status(401).json({ error: 'Invalid credentials' });
});

// Deliberately generic homepage so the site doesn't look obviously like a trap
app.get('/', (req, res) => {
  res.send('Welcome to the portal');
});

app.listen(PORT, () => {
  console.log(`Honeypot running on port ${PORT}`);
});