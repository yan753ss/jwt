require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const JWT_EXPIRES_IN = '15m';
const LOGIN_WINDOW_MS = 60 * 1000;
const MAX_FAILED_ATTEMPTS = 3;
const RESET_TOKEN_TTL_MS = 10 * 60 * 1000;
const ALLOW_PRIVILEGED_ROLE_REGISTRATION = process.env.ALLOW_PRIVILEGED_ROLE_REGISTRATION === 'true';
const logFile = path.join(__dirname, '..', 'auth.log');

let userIdCounter = 1;
const users = [];
const failedAttempts = new Map(); // key: username|ip
const resetTokens = new Map(); // key: token hash -> { userId, expiresAt }

const loginRateLimiter = rateLimit({
  windowMs: LOGIN_WINDOW_MS,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts from this IP, try later.' }
});

function sanitizeOutput(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function logLoginAttempt({ username, ip, success, reason }) {
  const line = `${new Date().toISOString()} username=${username || '-'} ip=${ip || '-'} success=${success} reason=${reason}\n`;
  fs.appendFileSync(logFile, line, 'utf8');
}

function getFailureKey(username, ip) {
  return `${username || ''}|${ip || ''}`;
}

function isTemporarilyBlocked(username, ip) {
  const key = getFailureKey(username, ip);
  const entry = failedAttempts.get(key);
  if (!entry) return false;

  if (Date.now() - entry.firstAttemptAt > LOGIN_WINDOW_MS) {
    failedAttempts.delete(key);
    return false;
  }

  return entry.count >= MAX_FAILED_ATTEMPTS;
}

function registerFailedAttempt(username, ip) {
  const key = getFailureKey(username, ip);
  const existing = failedAttempts.get(key);

  if (!existing || Date.now() - existing.firstAttemptAt > LOGIN_WINDOW_MS) {
    failedAttempts.set(key, { count: 1, firstAttemptAt: Date.now() });
    return;
  }

  existing.count += 1;
  failedAttempts.set(key, existing);
}

function clearFailedAttempts(username, ip) {
  failedAttempts.delete(getFailureKey(username, ip));
}

function issueToken(user) {
  const sessionId = crypto.randomUUID();
  user.activeSessionId = sessionId;
  user.lastLogin = new Date();

  return jwt.sign(
    { userId: user.id, role: user.role, sessionId },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function authenticate(req, res, next) {
  const auth = req.headers.authorization || '';
  const [scheme, token] = auth.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = users.find((u) => u.id === payload.userId);

    if (!user) {
      return res.status(401).json({ error: 'Invalid token user' });
    }

    if (user.activeSessionId !== payload.sessionId) {
      return res.status(401).json({ error: 'Session has been invalidated by a new login' });
    }

    req.user = payload;
    req.currentUser = user;
    return next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function authorize(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return next();
  };
}

app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  if (users.some((u) => u.username.toLowerCase() === String(username).toLowerCase())) {
    return res.status(409).json({ error: 'User already exists' });
  }

  const requestedRole = ['user', 'moderator', 'admin'].includes(role) ? role : 'user';
  const safeRole = (!ALLOW_PRIVILEGED_ROLE_REGISTRATION && requestedRole !== 'user') ? 'user' : requestedRole;
  const passwordHash = await bcrypt.hash(password, 10);

  const newUser = {
    id: userIdCounter++,
    username: String(username),
    passwordHash,
    role: safeRole,
    lastLogin: null,
    activeSessionId: null
  };

  users.push(newUser);

  return res.status(201).json({
    id: newUser.id,
    username: sanitizeOutput(newUser.username),
    role: newUser.role,
    lastLogin: newUser.lastLogin
  });
});

app.post('/login', loginRateLimiter, async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (!username || !password) {
    logLoginAttempt({ username, ip, success: false, reason: 'missing_credentials' });
    return res.status(400).json({ error: 'username and password are required' });
  }

  if (isTemporarilyBlocked(username, ip)) {
    logLoginAttempt({ username, ip, success: false, reason: 'too_many_failed_attempts' });
    return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
  }

  const user = users.find((u) => u.username.toLowerCase() === String(username).toLowerCase());
  if (!user) {
    registerFailedAttempt(username, ip);
    logLoginAttempt({ username, ip, success: false, reason: 'user_not_found' });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) {
    registerFailedAttempt(username, ip);
    logLoginAttempt({ username, ip, success: false, reason: 'invalid_password' });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  clearFailedAttempts(username, ip);
  const token = issueToken(user);
  logLoginAttempt({ username, ip, success: true, reason: 'ok' });

  return res.json({
    token,
    expiresIn: JWT_EXPIRES_IN,
    user: {
      id: user.id,
      username: sanitizeOutput(user.username),
      role: user.role,
      lastLogin: user.lastLogin
    }
  });
});

app.post('/token/refresh', authenticate, (req, res) => {
  const token = issueToken(req.currentUser);
  return res.json({ token, expiresIn: JWT_EXPIRES_IN });
});

app.post('/logout', authenticate, (req, res) => {
  req.currentUser.activeSessionId = null;
  return res.json({ message: 'Logged out' });
});

app.get('/me', authenticate, (req, res) => {
  return res.json({
    id: req.currentUser.id,
    username: sanitizeOutput(req.currentUser.username),
    role: req.currentUser.role,
    lastLogin: req.currentUser.lastLogin
  });
});

app.get('/moderator', authenticate, authorize('moderator', 'admin'), (req, res) => {
  return res.json({ message: 'Moderator area' });
});

app.get('/admin', authenticate, authorize('admin'), (req, res) => {
  return res.json({ message: 'Admin panel' });
});

app.post('/password-reset/request', (req, res) => {
  const { username } = req.body;
  const user = users.find((u) => u.username.toLowerCase() === String(username || '').toLowerCase());

  if (!user) {
    return res.json({ message: 'If user exists, reset token was generated.' });
  }

  const rawToken = crypto.randomBytes(24).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  resetTokens.set(tokenHash, {
    userId: user.id,
    expiresAt: Date.now() + RESET_TOKEN_TTL_MS
  });

  // In production send via secure channel (email).
  return res.json({
    message: 'Password reset token generated',
    resetToken: rawToken,
    expiresInMs: RESET_TOKEN_TTL_MS
  });
});

app.post('/password-reset/confirm', async (req, res) => {
  const { resetToken, newPassword } = req.body;
  if (!resetToken || !newPassword) {
    return res.status(400).json({ error: 'resetToken and newPassword are required' });
  }

  const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
  const tokenData = resetTokens.get(tokenHash);

  if (!tokenData || tokenData.expiresAt < Date.now()) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }

  const user = users.find((u) => u.id === tokenData.userId);
  if (!user) {
    resetTokens.delete(tokenHash);
    return res.status(400).json({ error: 'Invalid token user' });
  }

  user.passwordHash = await bcrypt.hash(newPassword, 10);
  user.activeSessionId = null;
  resetTokens.delete(tokenHash);

  return res.json({ message: 'Password updated successfully' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Auth service is running on port ${PORT}`);
  });
}

module.exports = { app, users, failedAttempts, resetTokens };
