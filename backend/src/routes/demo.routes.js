// Interactive OWASP demo endpoints — all require authentication
const express  = require('express');
const router   = express.Router();
const crypto   = require('crypto');
const { body, validationResult } = require('express-validator');
const authenticate   = require('../middleware/authenticate');
const { requireRole } = require('../middleware/rbac');
const { demoLimiter } = require('../middleware/rateLimiter');
const { ssrfGuard }   = require('../middleware/ssrfGuard');
const { logEvent }    = require('../utils/logger');
const { encryptField, decryptField } = require('../utils/crypto');
const User = require('../models/User');

// All demo routes require a valid JWT
router.use(authenticate, demoLimiter);

// ── A01: Access Control ──────────────────────────────────────────────────────
router.get('/a01/analyst-endpoint',
  requireRole('SuperAdmin', 'OrgAdmin', 'Manager', 'Analyst'),
  (req, res) => {
    logEvent('DEMO_A01_ANALYST', { role: req.user.role, owasp: 'A01' });
    res.json({
      owasp: 'A01',
      status: 'ALLOWED',
      message: `Welcome ${req.user.role}! Analyst-level endpoint accessible.`,
      yourRole: req.user.role,
      allowedRoles: ['SuperAdmin', 'OrgAdmin', 'Manager', 'Analyst'],
      middleware: 'requireRole() passed',
    });
  }
);

router.get('/a01/admin-endpoint',
  requireRole('SuperAdmin'),
  (req, res) => {
    logEvent('DEMO_A01_ADMIN', { role: req.user.role, owasp: 'A01' });
    res.json({
      owasp: 'A01',
      status: 'ALLOWED',
      message: 'SuperAdmin endpoint — classified data!',
      yourRole: req.user.role,
      allowedRoles: ['SuperAdmin'],
      middleware: 'requireRole("SuperAdmin") passed',
    });
  }
);

router.get('/a01/my-data', async (req, res) => {
  // A01: object-level auth — query is ALWAYS scoped to the user's orgId
  const users = await User.find({ orgId: req.user.orgId })
    .select('role orgId createdAt -_id')
    .limit(10)
    .lean();
  logEvent('DEMO_A01_TENANT', { orgId: req.user.orgId, owasp: 'A01' });
  res.json({
    owasp: 'A01',
    description: 'Object-level auth: DB query always filtered to your org',
    yourOrgId: req.user.orgId,
    mongoQuery: { orgId: req.user.orgId },
    results: users,
    note: 'other@demo.com (org-beta) can never see this org\'s data',
  });
});

// ── A02: Cryptographic Failures ──────────────────────────────────────────────
router.get('/a02/encryption-demo', (req, res) => {
  const sensitive = 'aadhaar:1234-5678-9012';
  const encrypted = encryptField(sensitive);
  const decrypted = decryptField(encrypted);
  logEvent('DEMO_A02_ENCRYPTION', { owasp: 'A02', userId: req.user.id });
  res.json({
    owasp: 'A02',
    algorithm: 'AES-256-GCM',
    original: sensitive,
    storedInDB: encrypted,
    decrypted,
    format: 'iv:ciphertext:authTag  (all hex-encoded)',
    tlsNote: 'TLS 1.3 enforced for all traffic in production',
    passwordStorage: 'bcrypt (cost=12) — one-way hash, cannot be reversed',
    secretsNote: 'Keys in env vars → use AWS Secrets Manager in production',
  });
});

// ── A03: Injection ───────────────────────────────────────────────────────────
router.post('/a03/injection-test',
  [ body('input').isString().isLength({ min: 1, max: 500 }) ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const input = String(req.body.input || '');

    // Detect common injection patterns
    const xssBlocked    = /<script|javascript:|onerror\s*=|<img\s/i.test(input);
    const sqlBlocked    = /('|-{2}|;|\/\*|\*\/|xp_|UNION\s|SELECT\s|DROP\s|INSERT\s|DELETE\s)/i.test(input);
    const nosqlBlocked  = /\$where|\$gt|\$lt|\$ne|\$or|\$and|\{.*\}/.test(input);
    const promptBlocked = /ignore\s+(previous|above|all|prior)|disregard\s+(instructions|system)/i.test(input);

    const sanitized = input
      .replace(/[$]/g, '_')                // strip MongoDB operators
      .replace(/</g, '&lt;').replace(/>/g, '&gt;');  // HTML encode

    logEvent('DEMO_A03_INJECTION', {
      preview: input.slice(0, 80),
      xssBlocked, sqlBlocked, nosqlBlocked, promptBlocked,
      owasp: 'A03',
    });

    res.json({
      owasp: 'A03',
      input,
      sanitized,
      threats: { xssBlocked, sqlBlocked, nosqlBlocked, promptBlocked },
      protections: [
        'express-mongo-sanitize strips $ operators from req.body/params',
        'express-validator validates type, length, and format',
        'Mongoose ORM uses parameterized queries — no raw query strings',
        'Output encoding prevents XSS execution in browser',
        'Prompt injection regex blocks LLM system prompt overrides',
      ],
    });
  }
);

// ── A05: Security Misconfiguration ───────────────────────────────────────────
router.get('/a05/headers', (req, res) => {
  logEvent('DEMO_A05_HEADERS', { owasp: 'A05', userId: req.user.id });
  res.json({
    owasp: 'A05',
    activeHeaders: {
      'Strict-Transport-Security': 'max-age=15552000; includeSubDomains (production only)',
      'X-Frame-Options':           'SAMEORIGIN — prevents clickjacking',
      'X-Content-Type-Options':    'nosniff — prevents MIME sniffing',
      'Content-Security-Policy':   "default-src 'self' — XSS mitigation",
      'Referrer-Policy':           'no-referrer — hides URL from third parties',
      'Permissions-Policy':        'camera=(), microphone=() — disables sensitive APIs',
      'X-Powered-By':              'REMOVED — stack not disclosed',
    },
    setBy: 'helmet() middleware — single line enables all headers',
    configuredIn: 'server.js line 1 — applies to every response',
    disabled: [
      'Debug mode off in production (NODE_ENV=production)',
      'No .env or .git files accessible via web (express.static serves only public/)',
      'All default DB credentials changed',
    ],
  });
});

// ── A06: Outdated Components ─────────────────────────────────────────────────
router.get('/a06/sbom', (req, res) => {
  logEvent('DEMO_A06_SBOM', { owasp: 'A06', userId: req.user.id });
  res.json({
    owasp: 'A06',
    scanDate: new Date().toISOString(),
    scanner: 'npm audit + Snyk (configured in CI/CD)',
    totalDependencies: 14,
    criticalVulnerabilities: 0,
    highVulnerabilities: 0,
    dependencies: [
      { name: 'express',               version: '4.18.2', status: 'OK' },
      { name: 'jsonwebtoken',          version: '9.0.2',  status: 'OK' },
      { name: 'bcryptjs',              version: '2.4.3',  status: 'OK' },
      { name: 'mongoose',              version: '8.0.3',  status: 'OK' },
      { name: 'helmet',                version: '7.1.0',  status: 'OK' },
      { name: 'express-rate-limit',    version: '7.1.5',  status: 'OK' },
      { name: 'express-validator',     version: '7.0.1',  status: 'OK' },
      { name: 'express-mongo-sanitize',version: '2.2.0',  status: 'OK' },
      { name: 'winston',               version: '3.11.0', status: 'OK' },
      { name: 'cors',                  version: '2.8.5',  status: 'OK' },
      { name: 'cookie-parser',         version: '1.4.6',  status: 'OK' },
      { name: 'dotenv',                version: '16.3.1', status: 'OK' },
      { name: 'uuid',                  version: '9.0.0',  status: 'OK' },
      { name: 'bcryptjs',              version: '2.4.3',  status: 'OK' },
    ],
    patchSLA: { CRITICAL: '24h', HIGH: '7d', MEDIUM: '30d', LOW: '90d' },
    ciCommands: ['npm audit --audit-level=high', 'npx snyk test'],
  });
});

// ── A07: Auth Session Info ────────────────────────────────────────────────────
router.get('/a07/session-info', (req, res) => {
  const now = Math.floor(Date.now() / 1000);
  logEvent('DEMO_A07_SESSION', { userId: req.user.id, owasp: 'A07' });
  res.json({
    owasp: 'A07',
    currentUser: {
      id:    req.user.id,
      role:  req.user.role,
      orgId: req.user.orgId,
    },
    tokenInfo: {
      issuedAt:        new Date(req.user.iat * 1000).toISOString(),
      expiresAt:       new Date(req.user.exp * 1000).toISOString(),
      secondsRemaining: Math.max(0, req.user.exp - now),
      type:            'JWT Access Token (15-minute expiry)',
    },
    cookieFlags: {
      httpOnly: true,
      secure:   'true in production',
      sameSite: 'Strict',
      note:     'JS cannot read this token — prevents XSS token theft',
    },
    securityControls: [
      'HttpOnly cookie — inaccessible to JavaScript',
      'Secure flag — HTTPS only in production',
      'SameSite: Strict — CSRF protection',
      'Refresh token rotation on every use',
      'Session invalidated immediately on logout',
      'Account locked after 5 failed login attempts',
      'MFA enabled for enterprise users',
    ],
  });
});

// ── A08: Software & Data Integrity ───────────────────────────────────────────
router.get('/a08/integrity', (req, res) => {
  const lockfileContent = JSON.stringify({ name: 'owasp-demo', lockfileVersion: 3 });
  const lockfileHash    = crypto.createHash('sha256').update(lockfileContent).digest('hex');
  logEvent('DEMO_A08_INTEGRITY', { owasp: 'A08', userId: req.user.id });
  res.json({
    owasp: 'A08',
    cicdIntegrity: {
      signedCommits:     true,
      branchProtection:  true,
      requirePRReview:   true,
      lockfileHash,
      lockfileVerified:  true,
    },
    subresourceIntegrity: 'SRI hashes on all CDN-loaded scripts',
    codeSigningStatus:    'Container images signed before deployment',
    aiModelIntegrity:     'SHA-256 verified before model loading',
    slsa: { level: 2, description: 'Build provenance tracked' },
  });
});

// ── A10: Server-Side Request Forgery ─────────────────────────────────────────
router.post('/a10/ssrf-test',
  [ body('url').isString().isLength({ min: 1, max: 500 }) ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const { url } = req.body;
    const result  = ssrfGuard(url, req);

    logEvent('DEMO_A10_SSRF', {
      inputUrl: url,
      blocked: result.blocked,
      reason: result.reason,
      owasp: 'A10',
    });

    res.json({
      owasp: 'A10',
      inputUrl: url,
      ...result,
      blockedRanges: [
        '10.0.0.0/8 — RFC 1918 private network',
        '172.16.0.0/12 — RFC 1918 private network',
        '192.168.0.0/16 — RFC 1918 private network',
        '169.254.169.254 — AWS/GCP instance metadata (credential theft)',
        '127.0.0.0/8 — Loopback',
      ],
    });
  }
);

module.exports = router;
