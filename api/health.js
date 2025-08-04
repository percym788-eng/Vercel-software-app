// api/health.js
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Database paths
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
  
  res.status(200).json({ 
    status: 'Server running', 
    timestamp: new Date().toISOString() 
  });
}
