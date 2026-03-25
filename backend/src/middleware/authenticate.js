// A07: JWT verification middleware
const jwt      = require('jsonwebtoken');
const { logEvent } = require('../utils/logger');

const authenticate = (req, res, next) => {
  // Accept token from HttpOnly cookie (preferred) or Authorization header
  const token =
    req.cookies?.accessToken ||
    req.headers.authorization?.replace(/^Bearer\s+/i, '');

  if (!token) {
    return res.status(401).json({ error: 'Authentication required — no token provided', owasp: 'A07' });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    const reason = err.name === 'TokenExpiredError' ? 'Token expired' : 'Token invalid';
    logEvent('AUTH_TOKEN_REJECTED', {
      reason,
      path: req.path,
      ip: req.ip,
      owasp: 'A07',
    });
    return res.status(401).json({ error: reason, owasp: 'A07' });
  }
};

module.exports = authenticate;
