// A09: Security Logging & Monitoring — persistent audit trail
const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  event: { type: String, required: true, index: true },
  userId: { type: String, index: true },
  role: { type: String },
  ip: { type: String },
  path: { type: String },
  method: { type: String },
  owasp: { type: String }, // which OWASP control triggered this
  details: { type: mongoose.Schema.Types.Mixed },
  severity: {
    type: String,
    enum: ['info', 'warn', 'error', 'critical'],
    default: 'info',
  },
}, {
  timestamps: true,
});

// A09: Retain logs for minimum 1 year — TTL index
auditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
