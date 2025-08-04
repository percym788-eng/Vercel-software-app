// api/admin/[...admin].js
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const USERS_DB = path.join('/tmp', 'server-users.json');
const SESSIONS_DB = path.join('/tmp', 'active-sessions.json');
const LOGS_DB = path.join('/tmp', 'access-logs.json');
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin-secret-key-change-this';

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

function requireAdmin(req, res) {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${ADMIN_TOKEN}`) {
    res.status(401).json({ error: 'Admin access required' });
    return false;
  }
  return true;
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (!requireAdmin(req, res)) return;

  initDatabases();
  
  const { admin } = req.query;
  const action = admin[0];

  try {
    switch (action) {
      case 'users':
        if (req.method === 'GET') {
          handleGetUsers(req, res);
        } else if (req.method === 'POST') {
          handleCreateUser(req, res);
        }
        break;
      case 'logs':
        handleGetLogs(req, res);
        break;
      default:
        res.status(404).json({ error: 'Admin endpoint not found' });
    }
  } catch (error) {
    console.error('Admin API Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

function handleGetUsers(req, res) {
  const users = loadDatabase(USERS_DB);
  const sessions = loadDatabase(SESSIONS_DB);
  
  const usersWithSessions = {};
  Object.keys(users).forEach(username => {
    usersWithSessions[username] = { ...users[username] };
    delete usersWithSessions[username].passwordHash;
    
    usersWithSessions[username].hasActiveSession = Object.values(sessions)
      .some(session => session.username === username);
  });
  
  res.json(usersWithSessions);
}

function handleCreateUser(req, res) {
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
}

function handleGetLogs(req, res) {
  const logs = loadDatabase(LOGS_DB);
  const limit = parseInt(req.query.limit) || 100;
  
  res.json(logs.slice(-limit).reverse());
}
