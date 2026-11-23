// Pattern-based detection of SQL injection and XSS in user input.
// Kept in its own file so both index.js and test_detection.js use the exact same code.

function detectAttackType(input) {
  // Normalize first: URL-decode and lowercase to catch basic encoding/case evasion
  let normalized;
  try {
    normalized = decodeURIComponent(input).toLowerCase();
  } catch (err) {
    normalized = input.toLowerCase(); // fallback if decoding fails
  }

  const sqliPatterns = [/('|--|;|\bor\b|\bunion\b|\bselect\b)/i];
  const xssPatterns = [/<script.*?>|javascript:|onerror\s*=|onload\s*=/i];

  if (sqliPatterns.some(pattern => pattern.test(normalized))) {
    return 'sqli_attempt';
  }
  if (xssPatterns.some(pattern => pattern.test(normalized))) {
    return 'xss_attempt';
  }
  return 'none';
}

module.exports = { detectAttackType };