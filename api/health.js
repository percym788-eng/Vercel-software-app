// pages/api/health.js - Health check endpoint
export default function handler(req, res) {
  if (req.method === 'GET') {
    res.status(200).json({
      success: true,
      message: 'Server is healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0'
    });
  } else {
    res.setHeader('Allow', ['GET']);
    res.status(405).json({ success: false, message: 'Method not allowed' });
  }
}

// pages/api/auth/login.js - User login endpoint
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

// In-memory user storage (replace with database in production)
const USERS = {
  'trial_user': {
    passwordHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', // 'demo123'
    plainPassword: 'demo123',
    accessType: 'trial',
    approved: true,
    createdAt: new Date().toISOString()
  },
  'admin_user': {
    passwordHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', // 'demo123'
    plainPassword: 'demo123',
    accessType: 'admin',
    approved: true,
    createdAt: new Date().toISOString()
  },
  'premium_user': {
    passwordHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', // 'demo123'
    plainPassword: 'demo123',
    accessType: 'unlimited',
    approved: true,
    createdAt: new Date().toISOString()
  }
};

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

export default function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    return res.status(405).json({ success: false, message: 'Method not allowed' });
  }

  const { username, password, deviceInfo } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Username and password are required'
    });
  }

  // Check if user exists
  const user = USERS[username];
  if (!user) {
    return res.status(401).json({
      success: false,
      message: 'Invalid username or password'
    });
  }

  // Verify password
  const passwordHash = hashPassword(password);
  if (passwordHash !== user.passwordHash) {
    return res.status(401).json({
      success: false,
      message: 'Invalid username or password'
    });
  }

  // Check if user is approved
  if (!user.approved) {
    return res.status(403).json({
      success: false,
      message: 'Account not approved'
    });
  }

  // Generate session
  const sessionId = crypto.randomBytes(32).toString('hex');
  const apiKey = process.env.GEMINI_API_KEY || "AIzaSyCsOGWrAgMVM6KAk4hbCb0Dk98aDLvwsv0";

  // Log authentication
  console.log(`Authentication successful: ${username} (${user.accessType})`);
  console.log(`Device: ${deviceInfo?.hostname || 'unknown'}`);

  return res.status(200).json({
    success: true,
    message: 'Authentication successful',
    accessType: user.accessType,
    sessionId,
    apiKey,
    user: {
      username,
      accessType: user.accessType,
      approved: user.approved
    },
    deviceInfo,
    timestamp: new Date().toISOString()
  });
}

// pages/api/admin/challenge.js - Admin challenge endpoint
import crypto from 'crypto';

// Store challenges temporarily (use Redis or database in production)
const challenges = new Map();

// Admin MAC addresses (should match your rsa-config.js)
const ADMIN_MAC_ADDRESSES = ['88:66:5a:46:b0:d0'];

export default function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    return res.status(405).json({ success: false, message: 'Method not allowed' });
  }

  const { deviceInfo } = req.body;

  if (!deviceInfo || !deviceInfo.macAddresses) {
    return res.status(400).json({
      success: false,
      message: 'Device information required'
    });
  }

  // Check if device is authorized for admin access
  const deviceMacs = deviceInfo.macAddresses.map(mac => mac.toLowerCase());
  const allowedMacs = ADMIN_MAC_ADDRESSES.map(mac => mac.toLowerCase());
  
  const isAuthorized = deviceMacs.some(mac => allowedMacs.includes(mac));
  
  if (!isAuthorized) {
    console.log(`Unauthorized admin attempt from MACs: ${deviceMacs.join(', ')}`);
    return res.status(403).json({
      success: false,
      message: 'Device not authorized for admin access'
    });
  }

  // Generate challenge
  const challenge = crypto.randomBytes(16).toString('hex');
  const sessionId = crypto.randomBytes(32).toString('hex');

  // Store challenge with 5-minute expiry
  challenges.set(sessionId, {
    challenge,
    timestamp: Date.now(),
    deviceInfo
  });

  // Clean up old challenges
  setTimeout(() => {
    challenges.delete(sessionId);
  }, 5 * 60 * 1000); // 5 minutes

  console.log(`Admin challenge generated for device: ${deviceInfo.hostname}`);

  return res.status(200).json({
    success: true,
    challenge,
    sessionId,
    timestamp: new Date().toISOString()
  });
}

// pages/api/admin/verify-signature.js - Verify admin signature
import crypto from 'crypto';

// RSA Public Key (should match your rsa-config.js)
const RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Dojkpn9uLlpJGfMnKJ/
G8DNP0F4uq78lrbCnZvKWFQmf3Mj3LoRWZPga9MYmSvfIbLJmaL/PMslxbDyXvI7
CIGCwPtZVqeE6S6UJ/EeD0EpJCNetWUOPOZ/Vqo+WrY/TaXQix/IzFNKXMj0Ul43
shU/BWM5lnPoxGtu2g0Z3hmhqDeHFQKG23V68K7d1xHhJkmlCVkSgQs+Oe/rkAHL
4g7vd1ViJ33dF4wKiWLKTmvcYOJXbNPE/RXwvb48qtPWoy2R1E0Jg52KNEUG2hDx
wmWRcyAv2bALB5G0EANaYQCieOethyykt2lo7rV7fy6jtxE+HoiGE0kLAmlbsoHc
wQIDAQAB
-----END PUBLIC KEY-----`;

// Import challenges from the challenge endpoint (in production, use shared storage)
import { challenges } from './challenge.js';

export default function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    return res.status(405).json({ success: false, message: 'Method not allowed' });
  }

  const { challenge, signature, sessionId, deviceInfo } = req.body;

  if (!challenge || !signature || !sessionId) {
    return res.status(400).json({
      success: false,
      message: 'Challenge, signature, and session ID are required'
    });
  }

  // Get stored challenge
  const storedChallenge = challenges.get(sessionId);
  if (!storedChallenge) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired session'
    });
  }

  // Check if challenge matches
  if (storedChallenge.challenge !== challenge) {
    return res.status(401).json({
      success: false,
      message: 'Challenge mismatch'
    });
  }

  // Check if challenge is not expired (5 minutes)
  if (Date.now() - storedChallenge.timestamp > 5 * 60 * 1000) {
    challenges.delete(sessionId);
    return res.status(401).json({
      success: false,
      message: 'Challenge expired'
    });
  }

  // Verify RSA signature
  try {
    const publicKey = crypto.createPublicKey({
      key: RSA_PUBLIC_KEY,
      format: 'pem',
      type: 'spki'
    });

    const isValid = crypto.verify(
      'sha256',
      Buffer.from(challenge),
      publicKey,
      Buffer.from(signature, 'base64')
    );

    if (!isValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid signature'
      });
    }

    // Generate admin token
    const adminToken = crypto.randomBytes(32).toString('hex');
    
    // Clean up challenge
    challenges.delete(sessionId);

    console.log(`Admin authentication successful for device: ${deviceInfo?.hostname || 'unknown'}`);

    return res.status(200).json({
      success: true,
      adminToken,
      permissions: ['full_access'],
      message: 'Admin authentication successful',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Signature verification error:', error);
    return res.status(500).json({
      success: false,
      message: 'Signature verification failed'
    });
  }
}

// pages/api/admin/users.js - User management endpoint
export default function handler(req, res) {
  // This would require admin authentication in production
  
  if (req.method === 'GET') {
    // Return user list (without passwords)
    const userList = Object.entries(USERS).map(([username, data]) => ({
      username,
      accessType: data.accessType,
      approved: data.approved,
      createdAt: data.createdAt
    }));

    return res.status(200).json({
      success: true,
      users: userList,
      total: userList.length
    });
  }

  res.setHeader('Allow', ['GET']);
  res.status(405).json({ success: false, message: 'Method not allowed' });
}
