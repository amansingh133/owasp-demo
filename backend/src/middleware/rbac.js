// A01: Broken Access Control — RBAC enforcement
const { logEvent } = require('../utils/logger');

const ROLES = ['SuperAdmin', 'OrgAdmin', 'Manager', 'Analyst', 'Viewer', 'API'];

// requireRole(...allowed) → only log FAILURES (success is too noisy for prod)
const requireRole = (...allowed) => (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthenticated', owasp: 'A01' });
  }

  if (!allowed.includes(req.user.role)) {
    logEvent('AUTHZ_FAILURE', {
      userId: req.user.id,
      userRole: req.user.role,
      requiredRoles: allowed,
      path: req.path,
      owasp: 'A01',
      severity: 'warn',
    });
    return res.status(403).json({
      error: 'Forbidden — insufficient role',
      yourRole: req.user.role,
      requiredRoles: allowed,
      owasp: 'A01',
      blocked: true,
    });
  }

  // Don't log every success — it floods the audit log with noise.
  // Only failures matter for security monitoring (A09).
  next();
};

// requireSameOrg — object-level authorization: resource must belong to user's org
const requireSameOrg = (getOrgId) => async (req, res, next) => {
  try {
    const resourceOrgId = await getOrgId(req);
    if (resourceOrgId && resourceOrgId.toString() !== req.user?.orgId?.toString()) {
      logEvent('OBJECT_LEVEL_AUTHZ_FAILURE', {
        userId: req.user?.id,
        userOrgId: req.user?.orgId,
        resourceOrgId,
        path: req.path,
        owasp: 'A01',
        severity: 'warn',
      });
      return res.status(403).json({ error: 'Cross-tenant access denied', owasp: 'A01' });
    }
    next();
  } catch (err) {
    next(err);
  }
};

module.exports = { requireRole, requireSameOrg, ROLES };
