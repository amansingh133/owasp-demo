require('dotenv').config();
const express        = require('express');
const path           = require('path');
const cors           = require('cors');
const helmet         = require('helmet');
const cookieParser   = require('cookie-parser');
const mongoSanitize  = require('express-mongo-sanitize');
const { apiLimiter } = require('./src/middleware/rateLimiter');
const { logEvent }   = require('./src/utils/logger');
const connectDB      = require('./src/config/db');

const app    = express();
const PORT   = process.env.PORT || 5000;
const isProd = process.env.NODE_ENV === 'production';

// ── A02 + A05: Security Headers ──────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'"],
      styleSrc:    ["'self'", "'unsafe-inline'"],
      imgSrc:      ["'self'", 'data:'],
      connectSrc:  ["'self'"],
      fontSrc:     ["'self'"],
      objectSrc:   ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: isProd ? { maxAge: 15552000, includeSubDomains: true } : false,
  // Remove X-Powered-By: Express — don't reveal the stack (A05)
  hidePoweredBy: true,
}));

// ── A05: CORS — no wildcards, specific origins only ─────────────────────────
const allowedOrigins = isProd
  ? [process.env.CLIENT_ORIGIN].filter(Boolean)
  : ['http://localhost:5173', 'http://localhost:5000'];

app.use(cors({
  origin: (origin, cb) => {
    // Allow server-to-server requests (no origin) and allowed origins
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('CORS policy: origin not allowed'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ── Body parsing — API4: max 10MB payload ───────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ── A03: Strip MongoDB $ operators from ALL incoming request bodies ──────────
app.use(mongoSanitize({ replaceWith: '_', onSanitizeError: () => {} }));

// ── A09: Security event logging — only log security-relevant requests ────────
// Log 4xx/5xx responses and sensitive endpoint hits; skip noisy 200s
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) return next();

  const start = Date.now();
  res.on('finish', () => {
    const status = res.statusCode;
    const ms     = Date.now() - start;

    // Always log auth events (regardless of status)
    const isAuthPath = req.path.startsWith('/auth/');
    // Always log failures (4xx/5xx)
    const isFailure  = status >= 400;
    // Skip noisy successful API reads in development
    const isNoisyGet = !isProd && req.method === 'GET' && status < 400 && !isAuthPath;

    if (!isNoisyGet || isFailure || isAuthPath) {
      logEvent('HTTP', {
        method: req.method,
        path: req.path,
        status,
        ms,
        ip: req.ip,
        ...(req.user?.id ? { userId: req.user.id } : {}),
      });
    }
  });
  next();
});

// ── Global rate limiter — 300 req/min (seed & health are exempt via skip()) ─
app.use('/api/', apiLimiter);

// ── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/auth',       require('./src/routes/auth.routes'));
app.use('/api/demo',       require('./src/routes/demo.routes'));
app.use('/api/compliance', require('./src/routes/compliance.routes'));

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), env: process.env.NODE_ENV });
});

// ── Serve React build (production SSR) ──────────────────────────────────────
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR, {
  maxAge: isProd ? '1d' : 0,
  setHeaders: (res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff'); // A05
  },
}));

// React Router catch-all — must be AFTER API routes
app.get('*', (req, res) => {
  const indexPath = path.join(PUBLIC_DIR, 'index.html');
  res.sendFile(indexPath, (err) => {
    if (err) {
      res.status(404).json({
        error: 'Frontend not built yet.',
        fix: 'Run: cd frontend && npm run build',
      });
    }
  });
});

// ── Global error handler ─────────────────────────────────────────────────────
// A09: Never expose stack traces in production
app.use((err, req, res, _next) => {
  logEvent('SERVER_ERROR', {
    message: err.message,
    path: req.path,
    method: req.method,
    owasp: 'A09',
    severity: 'error',
  });
  res.status(err.status || 500).json({
    error: isProd ? 'Internal server error' : err.message,
    ...(isProd ? {} : { stack: err.stack }),
  });
});

// ── Start ────────────────────────────────────────────────────────────────────
connectDB().then(() => {
  app.listen(PORT, () => {
    // Single clean startup banner — no duplicate output
    console.log([
      '',
      '🛡  OWASP Security Compliance Demo',
      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      `  Port : ${PORT}`,
      `  Env  : ${process.env.NODE_ENV || 'development'}`,
      '',
      '  Security controls active:',
      '    ✅ A01  RBAC middleware (6 roles)',
      '    ✅ A02  AES-256-GCM encryption + bcrypt',
      '    ✅ A03  express-mongo-sanitize + validation',
      '    ✅ A05  helmet() security headers',
      '    ✅ A07  JWT 15-min + rate limiting',
      '    ✅ A09  Winston audit logging + SSE stream',
      '    ✅ A10  SSRF guard',
      '    ✅ API4 300 req/min rate limit',
      '',
      '  → POST /api/auth/seed  to create demo users',
      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      '',
    ].join('\n'));
  });
}).catch((err) => {
  console.error('❌ Failed to start server:', err.message);
  process.exit(1);
});
