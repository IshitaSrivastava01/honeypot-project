// Converts attacks.log (one JSON object per line) into analytics/real_logs.csv for Power BI.
// Run with:  node convert_logs.js
const fs = require('fs');

const lines = fs.readFileSync('attacks.log', 'utf8').split(/\r?\n/).filter(l => l.trim());
const rows = [];
for (const line of lines) {
  try { rows.push(JSON.parse(line)); } catch (e) { /* skip broken lines */ }
}

const cols = ['timestamp', 'date', 'hour_utc', 'hour_ist', 'ip', 'endpoint', 'endpoint_base',
  'method', 'userAgent', 'eventType', 'query', 'detected_attack_type', 'flagged_brute_force'];

const esc = v => {
  if (v === undefined || v === null) return '';
  const s = String(v);
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};

const out = [cols.join(',')];
for (const r of rows) {
  const d = new Date(r.timestamp);
  const ist = new Date(d.getTime() + 5.5 * 3600 * 1000);
  const derived = {
    ...r,
    date: isNaN(d) ? '' : d.toISOString().slice(0, 10),
    hour_utc: isNaN(d) ? '' : d.getUTCHours(),
    hour_ist: isNaN(d) ? '' : ist.getUTCHours(),
    endpoint_base: (r.endpoint || '').split('?')[0],
  };
  out.push(cols.map(c => esc(derived[c])).join(','));
}

fs.mkdirSync('analytics', { recursive: true });
fs.writeFileSync('analytics/real_logs.csv', out.join('\n') + '\n');
console.log(`Wrote analytics/real_logs.csv with ${rows.length} rows`);
console.log('Columns:', cols.join(', '));