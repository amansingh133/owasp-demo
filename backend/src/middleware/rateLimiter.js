// A07 + API4: Rate Limiting
const rateLimit = require('express-rate-limit');
const { logEvent } = require('../utils/logger');

// ── Login limiter — strict: 5 failures per 15 min per IP ───────────────────
// skipSuccessfulRequests = true means only failed logins count toward the limit
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max: 5,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => 'login:' + req.ip,
  handler: (req, res) => {
    logEvent('RATE_LIMIT_LOGIN', {
      ip: req.ip,
      owasp: 'A07',
      severity: 'warn',
      message: 'Login rate limit hit — account temporarily locked',
    });
    res.status(429).json({
      error: 'Too many failed login attempts. Locked out for 15 minutes.',
      owasp: 'A07',
      attemptsUsed: req.rateLimit?.current,
      limit: req.rateLimit?.limit,
    });
  },
});

// ── API limiter — 300 req/min per authenticated user (or per IP if not authed)
// 300 is generous enough for normal use but still protects against scraping
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,        // 1 minute
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  // Key by user ID for authenticated requests, IP for unauthenticated
  keyGenerator: (req) => {
    if (req.user?.id) return 'user:' + req.user.id;
    return 'ip:' + req.ip;
  },
  skip: (req) => {
    // Never rate-limit the seed endpoint or health check
    return req.path === '/auth/seed' || req.path === '/health';
  },
  handler: (req, res) => {
    logEvent('RATE_LIMIT_API', {
      ip: req.ip,
      userId: req.user?.id,
      path: req.path,
      owasp: 'API4',
    });
    res.status(429).json({
      error: 'API rate limit exceeded. Max 300 requests/minute.',
      owasp: 'API4',
    });
  },
});

// ── Demo limiter — lenient, for interactive demo endpoints ─────────────────
const demoLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.id || req.ip,
  handler: (req, res) => {
    res.status(429).json({ error: 'Demo rate limit hit — slow down!' });
  },
});

module.exports = { loginLimiter, apiLimiter, demoLimiter };
