// A01 + A02 + A07: User model with RBAC roles and encrypted PII
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { encryptField, decryptField } = require('../utils/crypto');

const ROLES = ['SuperAdmin', 'OrgAdmin', 'Manager', 'Analyst', 'Viewer', 'API'];

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    // A02: Store email encrypted at rest
    set: (v) => encryptField(v),
    get: (v) => decryptField(v),
  },
  emailIndex: { type: String, unique: true }, // unencrypted hash for lookups
  password: { type: String, required: true }, // bcrypt hash — never plaintext
  role: {
    type: String,
    enum: ROLES,
    default: 'Viewer',
    required: true,
  },
  orgId: { type: String, default: 'org-default' }, // A01: tenant isolation
  // A07: Refresh token management
  refreshTokenHash: { type: String },
  refreshTokenExpiry: { type: Date },
  // A07: Session security
  passwordChangedAt: { type: Date },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date },
  // MFA placeholder
  mfaEnabled: { type: Boolean, default: false },
}, {
  timestamps: true,
  toJSON: { getters: true },
  toObject: { getters: true },
});

// A02: Hash password before save — bcrypt cost 12
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordChangedAt = new Date();
  next();
});

// A07: Compare password (never expose hash)
userSchema.methods.comparePassword = async function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

// A07: Check if account is locked
userSchema.methods.isLocked = function () {
  return this.lockUntil && this.lockUntil > Date.now();
};

// A07: Increment failed attempts, lock after 5
userSchema.methods.recordFailedLogin = async function () {
  this.loginAttempts += 1;
  if (this.loginAttempts >= 5) {
    this.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 min
  }
  return this.save();
};

userSchema.methods.resetLoginAttempts = async function () {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
  return this.save();
};

// Remove sensitive fields from JSON output
userSchema.methods.toSafeObject = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.refreshTokenHash;
  delete obj.emailIndex;
  return obj;
};

module.exports = mongoose.model('User', userSchema);
