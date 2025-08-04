// api/auth/[...auth].js
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Database paths
const USERS_DB = path.join('/tmp', 'server-users.json');
const SESSIONS_DB = path.join('/tmp', 'active-sessions.json');
const LOGS_DB = path.join('/tmp', 'access-logs.json');

// Helper functions
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
  
  if (logs.length > 1000) {
    logs.splice(0, logs.length - 1000);
  }
  
  saveDatabase(LOGS_DB, logs);
}

export default function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  initDatabases();
  
  const { auth } = req.query;
  const action = auth[0]; // login, validate, logout
  const clientIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';

  try {
    switch (action) {
      case 'login':
        handleLogin(req, res, clientIp);
        break;
      case 'validate':
        handleValidate(req, res, clientIp);
        break;
      case 'logout':
        handleLogout(req, res, clientIp);
        break;
      default:
        res.status(404).json({ error: 'Endpoint not found' });
    }
  } catch (error) {
    console.error('API Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

function handleLogin(req, res, clientIp) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { username, password } = req.body;
  
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
  
  if (!user.active) {
    logAccess(username, 'login', clientIp, false);
    return res.status(403).json({ error: 'Account deactivated' });
  }
  
  const passwordHash = hashPassword(password);
  if (user.passwordHash !== passwordHash) {
    logAccess(username, 'login', clientIp, false);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  if (user.accessType === 'trial' && user.usageCount >= (user.maxUsage || 1)) {
    logAccess(username, 'login', clientIp, false);
    return res.status(403).json({ error: 'Usage limit exceeded' });
  }
  
  const token = generateToken();
  const sessions = loadDatabase(SESSIONS_DB);
  
  // Remove old sessions for this user
  Object.keys(sessions).forEach(sessionToken => {
    if (sessions[sessionToken].username === username) {
      delete sessions[sessionToken];
    }
  });
  
  sessions[token] = {
    username,
    createdAt: new Date().toISOString(),
    lastAccess: new Date().toISOString(),
    ip: clientIp
  };
  
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
}

function handleValidate(req, res, clientIp) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: 'Token required' });
  }
  
  const sessions = loadDatabase(SESSIONS_DB);
  const session = sessions[token];
  
  if (!session) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  
  const sessionAge = Date.now() - new Date(session.createdAt).getTime();
  if (sessionAge > 24 * 60 * 60 * 1000) {
    delete sessions[token];
    saveDatabase(SESSIONS_DB, sessions);
    return res.status(401).json({ error: 'Session expired' });
  }
  
  sessions[token].lastAccess = new Date().toISOString();
  saveDatabase(SESSIONS_DB, sessions);
  
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
}

function handleLogout(req, res, clientIp) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { token } = req.body;
  
  if (token) {
    const sessions = loadDatabase(SESSIONS_DB);
    if (sessions[token]) {
      logAccess(sessions[token].username, 'logout', clientIp, true);
      delete sessions[token];
      saveDatabase(SESSIONS_DB, sessions);
    }
  }
  
  res.json({ success: true });
}
