// A07: Authentication routes — login, logout, refresh, /me, seed
const express  = require('express');
const router   = express.Router();
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');
const { body, validationResult } = require('express-validator');
const User         = require('../models/User');
const authenticate = require('../middleware/authenticate');
const { loginLimiter } = require('../middleware/rateLimiter');
const { logEvent }     = require('../utils/logger');

// A07: HttpOnly cookie options — Secure only in production
const COOKIE_OPTS = {
  httpOnly: true,
  secure:   process.env.NODE_ENV === 'production',
  sameSite: 'strict',
};

function signAccess(user) {
  return jwt.sign(
    { id: user._id, role: user.role, orgId: user.orgId, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }   // A07: short-lived
  );
}

function signRefresh(userId) {
  return jwt.sign({ sub: userId }, process.env.REFRESH_SECRET, { expiresIn: '7d' });
}

// ── POST /api/auth/login ─────────────────────────────────────────────────────
router.post('/login',
  loginLimiter,   // A07: 5 failures → 15-min lockout
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('password').isLength({ min: 8 }).withMessage('Password min 8 characters'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    try {
      const { email, password } = req.body;

      // A03: use hashed email for lookup (email field itself is AES-encrypted)
      const emailHash = crypto.createHash('sha256').update(email.toLowerCase()).digest('hex');
      const user = await User.findOne({ emailIndex: emailHash });

      if (!user) {
        logEvent('LOGIN_FAIL', { reason: 'User not found', ip: req.ip, owasp: 'A07' });
        // A07: same error for not-found and wrong password — prevents user enumeration
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // A07: check account lock before anything else
      if (user.isLocked()) {
        logEvent('LOGIN_LOCKED', { userId: user._id.toString(), ip: req.ip, owasp: 'A07' });
        return res.status(423).json({
          error: 'Account locked after too many failed attempts. Try again in 15 minutes.',
          owasp: 'A07',
        });
      }

      const valid = await user.comparePassword(password);
      if (!valid) {
        await user.recordFailedLogin();
        logEvent('LOGIN_FAIL', {
          userId: user._id.toString(),
          attempts: user.loginAttempts,
          ip: req.ip,
          owasp: 'A07',
        });
        return res.status(401).json({
          error: 'Invalid email or password',
          attemptsRemaining: Math.max(0, 5 - user.loginAttempts),
        });
      }

      // Success — reset attempts and issue tokens
      await user.resetLoginAttempts();

      const accessToken  = signAccess(user);
      const refreshToken = signRefresh(user._id);

      // A07: store only the bcrypt hash of the refresh token — never the token itself
      user.refreshTokenHash   = await bcrypt.hash(refreshToken, 10);
      user.refreshTokenExpiry = new Date(Date.now() + 7 * 86400000);
      await user.save();

      // A07: set as HttpOnly cookies so JS cannot access them
      res.cookie('accessToken',  accessToken,  { ...COOKIE_OPTS, maxAge: 15 * 60 * 1000 });
      res.cookie('refreshToken', refreshToken, { ...COOKIE_OPTS, maxAge: 7 * 86400000, path: '/api/auth/refresh' });

      logEvent('LOGIN_SUCCESS', {
        userId: user._id.toString(),
        role: user.role,
        orgId: user.orgId,
        ip: req.ip,
        owasp: 'A07',
      });

      res.json({
        message: 'Login successful',
        user: user.toSafeObject(),
        accessToken,   // also in body for convenience
      });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ error: 'Server error during login' });
    }
  }
);

// ── POST /api/auth/refresh ───────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token) return res.status(401).json({ error: 'No refresh token provided' });

  try {
    const { sub: userId } = jwt.verify(token, process.env.REFRESH_SECRET);
    const user = await User.findById(userId);

    if (!user || !user.refreshTokenHash || !user.refreshTokenExpiry || user.refreshTokenExpiry < new Date()) {
      return res.status(401).json({ error: 'Refresh token expired or invalid' });
    }

    const valid = await bcrypt.compare(token, user.refreshTokenHash);
    if (!valid) {
      logEvent('REFRESH_TOKEN_MISMATCH', { userId, ip: req.ip, owasp: 'A07' });
      return res.status(401).json({ error: 'Refresh token mismatch — possible token theft' });
    }

    // A07: rotate both tokens on every refresh
    const newAccess  = signAccess(user);
    const newRefresh = signRefresh(user._id);

    user.refreshTokenHash   = await bcrypt.hash(newRefresh, 10);
    user.refreshTokenExpiry = new Date(Date.now() + 7 * 86400000);
    await user.save();

    res.cookie('accessToken',  newAccess,  { ...COOKIE_OPTS, maxAge: 15 * 60 * 1000 });
    res.cookie('refreshToken', newRefresh, { ...COOKIE_OPTS, maxAge: 7 * 86400000, path: '/api/auth/refresh' });

    logEvent('TOKEN_REFRESHED', { userId: user._id.toString(), owasp: 'A07' });
    res.json({ accessToken: newAccess, user: user.toSafeObject() });
  } catch (err) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// ── GET /api/auth/me ─────────────────────────────────────────────────────────
router.get('/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user: user.toSafeObject() });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── POST /api/auth/logout ────────────────────────────────────────────────────
router.post('/logout', authenticate, async (req, res) => {
  try {
    // A07: invalidate the refresh token in DB immediately on logout
    await User.findByIdAndUpdate(req.user.id, {
      $unset: { refreshTokenHash: '', refreshTokenExpiry: '' },
    });
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken', { path: '/api/auth/refresh' });
    logEvent('LOGOUT', { userId: req.user.id, owasp: 'A07' });
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error during logout' });
  }
});

// ── POST /api/auth/seed — create demo users (no auth required, no rate limit)
// This endpoint is exempt from apiLimiter via the skip() function
router.post('/seed', async (req, res) => {
  const demoUsers = [
    { email: 'admin@demo.com',   password: 'Demo@Password123', role: 'SuperAdmin', orgId: 'org-alpha' },
    { email: 'manager@demo.com', password: 'Demo@Password123', role: 'Manager',    orgId: 'org-alpha' },
    { email: 'analyst@demo.com', password: 'Demo@Password123', role: 'Analyst',    orgId: 'org-alpha' },
    { email: 'viewer@demo.com',  password: 'Demo@Password123', role: 'Viewer',     orgId: 'org-alpha' },
    { email: 'other@demo.com',   password: 'Demo@Password123', role: 'Analyst',    orgId: 'org-beta'  },
  ];

  try {
    const results = [];
    for (const u of demoUsers) {
      const emailHash = crypto.createHash('sha256').update(u.email.toLowerCase()).digest('hex');
      const exists    = await User.findOne({ emailIndex: emailHash });
      if (!exists) {
        const user = new User({ ...u, emailIndex: emailHash });
        await user.save();
        results.push({ email: u.email, role: u.role, orgId: u.orgId, created: true });
      } else {
        results.push({ email: u.email, role: u.role, orgId: u.orgId, created: false, note: 'already exists' });
      }
    }
    logEvent('DEMO_SEED', { count: results.filter(r => r.created).length });
    res.json({ message: 'Seed complete', users: results });
  } catch (err) {
    console.error('Seed error:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
