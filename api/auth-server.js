// api/auth-server.js - Modified for Vercel
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Use /tmp directory for Vercel (writable directory)
const USERS_DB = path.join('/tmp', 'server-users.json');
const SESSIONS_DB = path.join('/tmp', 'active-sessions.json');
const LOGS_DB = path.join('/tmp', 'access-logs.json');

// Initialize databases
function initDatabases() {
  if (!fs.existsSync(USERS_DB)) {
    fs.writeFileSync(USERS_DB, JSON.stringify({}, null, 2));
  }
  if (!fs.existsSync(SESSIONS_DB)) {
    fs.writeFileSync(SESSIONS_DB, JSON.stringify({}, null, 2));
  }
  if (!fs.existsSync(LOGS_DB)) {
    fs.writeFileSync(LOGS_DB, JSON.stringify([], null, 2));
  }
}

// Helper functions
function loadDatabase(dbPath) {
  try {
    return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  } catch (error) {
    return dbPath === LOGS_DB ? [] : {};
  }
}

function saveDatabase(dbPath, data) {
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function logAccess(username, action, ip, success = true) {
  const logs = loadDatabase(LOGS_DB);
  logs.push({
    username,
    action,
    ip,
    success,
    timestamp: new Date().toISOString()
  });
  
  // Keep only last 1000 logs
  if (logs.length > 1000) {
    logs.splice(0, logs.length - 1000);
  }
  
  saveDatabase(LOGS_DB, logs);
}

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'Server running', timestamp: new Date().toISOString() });
});

// User authentication
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
  
  if (!username || !password) {
    logAccess(username || 'unknown', 'login', clientIp, false);
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  const users = loadDatabase(USERS_DB);
  const user = users[username];
  
  if (!user) {
    logAccess(username, 'login', clientIp, false);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Check if user is active
  if (!user.active) {
    logAccess(username, 'login', clientIp, false);
    return res.status(403).json({ error: 'Account deactivated' });
  }
  
  // Verify password
  const passwordHash = hashPassword(password);
  if (user.passwordHash !== passwordHash) {
    logAccess(username, 'login', clientIp, false);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Check usage limits
  if (user.accessType === 'trial' && user.usageCount >= (user.maxUsage || 1)) {
    logAccess(username, 'login', clientIp, false);
    return res.status(403).json({ error: 'Usage limit exceeded' });
  }
  
  // Generate session token
  const token = generateToken();
  const sessions = loadDatabase(SESSIONS_DB);
  
  // Remove old sessions for this user
  Object.keys(sessions).forEach(sessionToken => {
    if (sessions[sessionToken].username === username) {
      delete sessions[sessionToken];
    }
  });
  
  // Create new session
  sessions[token] = {
    username,
    createdAt: new Date().toISOString(),
    lastAccess: new Date().toISOString(),
    ip: clientIp
  };
  
  // Update user usage
  users[username].usageCount = (users[username].usageCount || 0) + 1;
  users[username].lastLogin = new Date().toISOString();
  users[username].lastIp = clientIp;
  
  saveDatabase(SESSIONS_DB, sessions);
  saveDatabase(USERS_DB, users);
  logAccess(username, 'login', clientIp, true);
  
  res.json({
    success: true,
    token,
    user: {
      username,
      accessType: user.accessType,
      usageCount: user.usageCount,
      maxUsage: user.maxUsage,
      expiresAt: user.expiresAt
    }
  });
});

// Validate session token
app.post('/auth/validate', (req, res) => {
  const { token } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
  
  if (!token) {
    return res.status(400).json({ error: 'Token required' });
  }
  
  const sessions = loadDatabase(SESSIONS_DB);
  const session = sessions[token];
  
  if (!session) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  
  // Check if session is too old (24 hours)
  const sessionAge = Date.now() - new Date(session.createdAt).getTime();
  if (sessionAge > 24 * 60 * 60 * 1000) {
    delete sessions[token];
    saveDatabase(SESSIONS_DB, sessions);
    return res.status(401).json({ error: 'Session expired' });
  }
  
  // Update last access
  sessions[token].lastAccess = new Date().toISOString();
  saveDatabase(SESSIONS_DB, sessions);
  
  // Get user info
  const users = loadDatabase(USERS_DB);
  const user = users[session.username];
  
  if (!user || !user.active) {
    delete sessions[token];
    saveDatabase(SESSIONS_DB, sessions);
    return res.status(403).json({ error: 'Account deactivated' });
  }
  
  logAccess(session.username, 'validate', clientIp, true);
  
  res.json({
    valid: true,
    user: {
      username: session.username,
      accessType: user.accessType,
      usageCount: user.usageCount,
      maxUsage: user.maxUsage
    }
  });
});

// Logout
app.post('/auth/logout', (req, res) => {
  const { token } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
  
  if (token) {
    const sessions = loadDatabase(SESSIONS_DB);
    if (sessions[token]) {
      logAccess(sessions[token].username, 'logout', clientIp, true);
      delete sessions[token];
      saveDatabase(SESSIONS_DB, sessions);
    }
  }
  
  res.json({ success: true });
});

// Admin routes (protected)
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin-secret-key-change-this';

function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${ADMIN_TOKEN}`) {
    return res.status(401).json({ error: 'Admin access required' });
  }
  next();
}

// Get all users (admin only)
app.get('/admin/users', requireAdmin, (req, res) => {
  const users = loadDatabase(USERS_DB);
  const sessions = loadDatabase(SESSIONS_DB);
  
  // Add session info to users
  const usersWithSessions = {};
  Object.keys(users).forEach(username => {
    usersWithSessions[username] = { ...users[username] };
    delete usersWithSessions[username].passwordHash; // Don't send password hash
    
    // Check if user has active session
    usersWithSessions[username].hasActiveSession = Object.values(sessions)
      .some(session => session.username === username);
  });
  
  res.json(usersWithSessions);
});

// Create user (admin only)
app.post('/admin/users', requireAdmin, (req, res) => {
  const { username, password, accessType, maxUsage, expiresAt } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  const users = loadDatabase(USERS_DB);
  
  if (users[username]) {
    return res.status(409).json({ error: 'User already exists' });
  }
  
  users[username] = {
    passwordHash: hashPassword(password),
    accessType: accessType || 'trial',
    maxUsage: maxUsage || 1,
    usageCount: 0,
    active: true,
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt || null
  };
  
  saveDatabase(USERS_DB, users);
  
  res.json({ success: true, message: 'User created successfully' });
});

// Delete user (admin only)
app.delete('/admin/users/:username', requireAdmin, (req, res) => {
  const { username } = req.params;
  const users = loadDatabase(USERS_DB);
  const sessions = loadDatabase(SESSIONS_DB);
  
  if (!users[username]) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // Remove user
  delete users[username];
  
  // Remove all sessions for this user
  Object.keys(sessions).forEach(token => {
    if (sessions[token].username === username) {
      delete sessions[token];
    }
  });
  
  saveDatabase(USERS_DB, users);
  saveDatabase(SESSIONS_DB, sessions);
  
  res.json({ success: true, message: 'User deleted successfully' });
});

// Deactivate user (admin only)
app.patch('/admin/users/:username/deactivate', requireAdmin, (req, res) => {
  const { username } = req.params;
  const users = loadDatabase(USERS_DB);
  const sessions = loadDatabase(SESSIONS_DB);
  
  if (!users[username]) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  users[username].active = false;
  users[username].deactivatedAt = new Date().toISOString();
  
  // Remove all active sessions
  Object.keys(sessions).forEach(token => {
    if (sessions[token].username === username) {
      delete sessions[token];
    }
  });
  
  saveDatabase(USERS_DB, users);
  saveDatabase(SESSIONS_DB, sessions);
  
  res.json({ success: true, message: 'User deactivated successfully' });
});

// Get access logs (admin only)
app.get('/admin/logs', requireAdmin, (req, res) => {
  const logs = loadDatabase(LOGS_DB);
  const limit = parseInt(req.query.limit) || 100;
  
  res.json(logs.slice(-limit).reverse()); // Most recent first
});

// Get active sessions (admin only)
app.get('/admin/sessions', requireAdmin, (req, res) => {
  const sessions = loadDatabase(SESSIONS_DB);
  res.json(sessions);
});

// Initialize databases when module loads
initDatabases();

// Export for Vercel
module.exports = app;
