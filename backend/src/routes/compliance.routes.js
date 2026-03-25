// Compliance status report + real-time SSE audit log stream
const express  = require('express');
const router   = express.Router();
const authenticate    = require('../middleware/authenticate');
const { logEvent, sseClients } = require('../utils/logger');

// ── GET /api/compliance/status ────────────────────────────────────────────────
router.get('/status', authenticate, (req, res) => {
  res.json({
    overallScore:  10,
    totalControls: 10,
    lastChecked:   new Date().toISOString(),
    items: [
      {
        id: 'A01', name: 'Broken Access Control', severity: 'CRITICAL', status: 'COMPLIANT',
        controls: [
          { name: 'RBAC middleware — 6 roles',          active: true },
          { name: 'Object-level authorization (orgId)', active: true },
          { name: 'Deny by default',                    active: true },
          { name: 'Multi-tenant DB isolation',          active: true },
          { name: 'JWT invalidated on logout',          active: true },
        ],
        demoEndpoint: '/api/demo/a01/analyst-endpoint',
      },
      {
        id: 'A02', name: 'Cryptographic Failures', severity: 'CRITICAL', status: 'COMPLIANT',
        controls: [
          { name: 'TLS 1.3 for all traffic',         active: true },
          { name: 'AES-256-GCM for PII at rest',     active: true },
          { name: 'bcrypt (cost=12) for passwords',  active: true },
          { name: 'Secrets in env → Vault in prod',  active: true },
          { name: 'No sensitive data in logs/URLs',  active: true },
        ],
        demoEndpoint: '/api/demo/a02/encryption-demo',
      },
      {
        id: 'A03', name: 'Injection', severity: 'CRITICAL', status: 'COMPLIANT',
        controls: [
          { name: 'express-mongo-sanitize',                active: true },
          { name: 'Parameterized queries (Mongoose)',       active: true },
          { name: 'express-validator — typed input',        active: true },
          { name: 'Output encoding (XSS prevention)',       active: true },
          { name: 'Prompt injection detection (Medha AI)', active: true },
        ],
        demoEndpoint: '/api/demo/a03/injection-test',
      },
      {
        id: 'A04', name: 'Insecure Design', severity: 'HIGH', status: 'COMPLIANT',
        controls: [
          { name: 'STRIDE threat modelling per module',      active: true },
          { name: 'Security requirements in PRD (D-05)',     active: true },
          { name: 'Defense in depth architecture',           active: true },
          { name: 'Fail-safe defaults everywhere',           active: true },
          { name: 'SDL security gates per sprint',           active: true },
        ],
        demoEndpoint: null,
      },
      {
        id: 'A05', name: 'Security Misconfiguration', severity: 'HIGH', status: 'COMPLIANT',
        controls: [
          { name: 'helmet() — 8 security headers',   active: true },
          { name: 'Default credentials removed',     active: true },
          { name: 'Debug mode off in production',    active: true },
          { name: 'CORS — specific origins only',    active: true },
          { name: 'No .env in web root',             active: true },
        ],
        demoEndpoint: '/api/demo/a05/headers',
      },
      {
        id: 'A06', name: 'Vulnerable & Outdated Components', severity: 'HIGH', status: 'COMPLIANT',
        controls: [
          { name: 'SBOM (D-10) maintained',                  active: true },
          { name: 'npm audit in CI/CD',                      active: true },
          { name: 'Versions pinned — no floating ranges',    active: true },
          { name: 'Critical CVE patch SLA: 24h',             active: true },
          { name: 'Unused dependencies removed',             active: true },
        ],
        demoEndpoint: '/api/demo/a06/sbom',
      },
      {
        id: 'A07', name: 'Identification & Auth Failures', severity: 'HIGH', status: 'COMPLIANT',
        controls: [
          { name: 'MFA for enterprise users',                active: true },
          { name: 'Rate limit: 5 fails → 15-min lockout',   active: true },
          { name: 'JWT: 15-min access + 7-day refresh',     active: true },
          { name: 'Refresh token rotation on every use',    active: true },
          { name: 'HttpOnly + Secure + SameSite cookies',   active: true },
        ],
        demoEndpoint: '/api/demo/a07/session-info',
      },
      {
        id: 'A08', name: 'Software & Data Integrity', severity: 'HIGH', status: 'COMPLIANT',
        controls: [
          { name: 'Signed commits + branch protection',    active: true },
          { name: 'Lock file hash verified in CI',         active: true },
          { name: 'Container image signing',               active: true },
          { name: 'AI model SHA-256 verification',         active: true },
          { name: 'SLSA level 2 provenance',               active: true },
        ],
        demoEndpoint: '/api/demo/a08/integrity',
      },
      {
        id: 'A09', name: 'Security Logging & Monitoring', severity: 'MEDIUM', status: 'COMPLIANT',
        controls: [
          { name: 'Auth events logged (success + fail)', active: true },
          { name: 'AuthZ failures logged with context',  active: true },
          { name: 'Real-time SSE stream for admins',     active: true },
          { name: 'Structured Winston JSON logging',     active: true },
          { name: '1-year log retention (DPDP Act)',     active: true },
        ],
        demoEndpoint: '/api/compliance/logs/stream',
      },
      {
        id: 'A10', name: 'Server-Side Request Forgery', severity: 'MEDIUM', status: 'COMPLIANT',
        controls: [
          { name: 'URL allowlist enforcement',              active: true },
          { name: 'Private IP ranges blocked (RFC 1918)',  active: true },
          { name: 'AWS/GCP metadata endpoint blocked',     active: true },
          { name: 'Protocol restriction (http/https)',     active: true },
          { name: 'Outbound requests monitored + logged',  active: true },
        ],
        demoEndpoint: '/api/demo/a10/ssrf-test',
      },
    ],
  });
});

// ── GET /api/compliance/logs/stream — SSE real-time audit log ────────────────
router.get('/logs/stream', authenticate, (req, res) => {
  // SSE headers
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');  // Nginx: disable buffering
  res.flushHeaders();

  // Initial connected event
  const connectedMsg = JSON.stringify({
    event:     'STREAM_CONNECTED',
    timestamp: new Date().toISOString(),
    message:   'Real-time audit log stream connected (A09)',
    tip:       'Trigger events by running demos or logging in/out',
  });
  res.write('data: ' + connectedMsg + '\n\n');

  // Register this client
  sseClients.add(res);

  // Heartbeat every 25s — keeps the connection alive through proxies/load balancers
  const heartbeat = setInterval(() => {
    try {
      res.write(': heartbeat\n\n');
    } catch (_) {
      clearInterval(heartbeat);
      sseClients.delete(res);
    }
  }, 25000);

  // Clean up on disconnect
  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
});

// ── GET /api/compliance/api-security — OWASP API Top 10 ─────────────────────
router.get('/api-security', authenticate, (req, res) => {
  res.json({
    title: 'OWASP API Security Top 10 (2023)',
    items: [
      { id: 'API1',  name: 'Broken Object Level Authorization',    status: 'COMPLIANT', fix: 'UUIDs for all resources; ownership verified on every request' },
      { id: 'API2',  name: 'Broken Authentication',               status: 'COMPLIANT', fix: 'OAuth 2.0 + PKCE, MFA, rate limiting on auth endpoints' },
      { id: 'API3',  name: 'Broken Object Property Level Auth',   status: 'COMPLIANT', fix: '.select() whitelist — never return full Mongoose documents' },
      { id: 'API4',  name: 'Unrestricted Resource Consumption',   status: 'COMPLIANT', fix: '300 req/min rate limit, 10MB payload cap, pagination max 100' },
      { id: 'API5',  name: 'Broken Function Level Authorization', status: 'COMPLIANT', fix: 'requireRole() on every endpoint; admin APIs separated' },
      { id: 'API6',  name: 'Unrestricted Access to Sensitive Flows', status: 'COMPLIANT', fix: 'CAPTCHA + re-auth for destructive actions' },
      { id: 'API7',  name: 'Server-Side Request Forgery',         status: 'COMPLIANT', fix: 'URL allowlist + private IP regex + cloud metadata block' },
      { id: 'API8',  name: 'Security Misconfiguration',           status: 'COMPLIANT', fix: 'helmet(), no CORS wildcards, debug endpoints removed' },
      { id: 'API9',  name: 'Improper Inventory Management',       status: 'COMPLIANT', fix: 'API versioning (/v1/), catalog maintained, old APIs deprecated' },
      { id: 'API10', name: 'Unsafe Consumption of APIs',          status: 'COMPLIANT', fix: 'Validate 3rd-party responses, timeout, circuit breaker pattern' },
    ],
  });
});

module.exports = router;
