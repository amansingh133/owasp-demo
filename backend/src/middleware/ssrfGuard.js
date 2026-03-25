// A10: Server-Side Request Forgery (SSRF) Prevention
const { logEvent } = require('../utils/logger');

const PRIVATE_IP_REGEX = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|::1|fc|fd)/i;
const BLOCKED_HOSTNAMES = ['metadata.google.internal', 'metadata.aws.internal'];
const CLOUD_METADATA = /^169\.254\.169\.254/;

function ssrfGuard(rawUrl, req = {}) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { blocked: true, reason: 'Invalid URL format', url: rawUrl };
  }

  const hostname = parsed.hostname;

  if (PRIVATE_IP_REGEX.test(hostname)) {
    const reason = CLOUD_METADATA.test(hostname)
      ? 'Blocked: AWS/GCP metadata endpoint (credential theft vector)'
      : 'Blocked: Private IP range — internal network access denied';
    logEvent('SSRF_BLOCKED', { url: rawUrl, hostname, reason, ip: req.ip, owasp: 'A10' });
    return { blocked: true, reason, hostname, owasp: 'A10' };
  }

  if (BLOCKED_HOSTNAMES.includes(hostname)) {
    const reason = 'Blocked: Cloud metadata hostname';
    logEvent('SSRF_BLOCKED', { url: rawUrl, hostname, reason, owasp: 'A10' });
    return { blocked: true, reason, hostname, owasp: 'A10' };
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { blocked: true, reason: 'Blocked: Only http/https protocols allowed' };
  }

  logEvent('SSRF_ALLOWED', { url: rawUrl, hostname, ip: req.ip });
  return { blocked: false, hostname, protocol: parsed.protocol };
}

module.exports = { ssrfGuard };
