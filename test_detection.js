// Detection test: runs a set of PayloadsAllTheThings attack payloads and normal inputs through
// detectAttackType() and reports detection rate and false positives.
//
// Run with:  node test_detection.js

const { detectAttackType } = require('./detector');

// ---- Attack payloads: loaded from files taken from PayloadsAllTheThings ----
// payloads_sqli.txt = SQL Injection/Intruder/Auth_Bypass.txt (all lines)
// payloads_xss.txt  = XSS Injection/README.md, lines starting with "<" that contain a JS call
//                     (alert / confirm / eval / document.)
const fs = require('fs');
const loadLines = f => fs.readFileSync(f, 'utf8').split(/\r?\n/).filter(l => l.trim() !== '');
const sqliPayloads = loadLines('payloads_sqli.txt');
const xssPayloads = loadLines('payloads_xss.txt');

// ---- Normal, harmless inputs ----
const normalInputs = [
  "laptop",
  "wireless headphones",
  "red running shoes",
  "how to reset password",
  "pizza near me",
  "weather today",
  "python tutorial",
  "order status 12345",
  "john smith",
  "contact us",
  "return policy",
  "size 10 shoes",
  "usb-c cable",
  "coffee or tea",
  "rock; paper; scissors",
  "o'brien",
  "women's jackets",
  "select a gift",
  "union station hours",
  "what's new",
  "terms and conditions",
  "user@example.com",
  "10% off",
  "C++ books",
  "best budget phone 2026",
];

// ---- Run ----
const attackCases = [
  ...sqliPayloads.map(p => ({ payload: p, expected: 'sqli_attempt' })),
  ...xssPayloads.map(p => ({ payload: p, expected: 'xss_attempt' })),
];

let detected = 0;
let correctlyLabelled = 0;
const missed = [];
const mislabelled = [];

for (const c of attackCases) {
  const result = detectAttackType(c.payload);
  if (result !== 'none') {
    detected++;
    if (result === c.expected) {
      correctlyLabelled++;
    } else {
      mislabelled.push({ payload: c.payload, expected: c.expected, got: result });
    }
  } else {
    missed.push(c);
  }
}

const falsePositives = [];
for (const input of normalInputs) {
  const result = detectAttackType(input);
  if (result !== 'none') {
    falsePositives.push({ input, flagged_as: result });
  }
}

// ---- Report ----
console.log('\n=== Detection test report ===\n');

console.log(`Attack payloads tested:     ${attackCases.length}  (${sqliPayloads.length} SQLi + ${xssPayloads.length} XSS)`);
console.log(`Detected (any attack label): ${detected} of ${attackCases.length}  (${(detected / attackCases.length * 100).toFixed(1)}%)`);
console.log(`Correct attack category:     ${correctlyLabelled} of ${attackCases.length}  (${(correctlyLabelled / attackCases.length * 100).toFixed(1)}%)`);
console.log(`Missed:                      ${missed.length}`);
console.log(`Normal inputs tested:        ${normalInputs.length}`);
console.log(`False positives:             ${falsePositives.length} of ${normalInputs.length}  (${(falsePositives.length / normalInputs.length * 100).toFixed(1)}%)`);

if (missed.length) {
  console.log('\n--- MISSED attack payloads (detector said "none") ---');
  missed.forEach(m => console.log(`  [${m.expected}] ${m.payload}`));
}

if (mislabelled.length) {
  console.log('\n--- Detected, but with the wrong category ---');
  mislabelled.forEach(m => console.log(`  expected ${m.expected}, got ${m.got}:  ${m.payload}`));
}

if (falsePositives.length) {
  console.log('\n--- FALSE POSITIVES (normal input flagged as an attack) ---');
  falsePositives.forEach(f => console.log(`  "${f.input}"  ->  ${f.flagged_as}`));
}

console.log('\nSummary line for README / resume (test payloads, not live traffic):');
console.log(`  "Detected ${detected} of ${attackCases.length} PayloadsAllTheThings attack payloads (${(detected / attackCases.length * 100).toFixed(0)}%), with ${falsePositives.length} false positives on ${normalInputs.length} normal inputs."\n`);