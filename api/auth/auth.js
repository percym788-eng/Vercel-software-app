// /api/auth.js - Regular user authentication endpoint
import crypto from 'crypto';

// User database (in production, use a real database)
const USERS = {
    // Trial users (30 minute limit)
    'demo1': { password: 'trial2024', accessType: 'trial', approved: true },
    'trial_user': { password: 'demo123', accessType: 'trial', approved: true },
    'test_user': { password: 'demo123', accessType: 'trial', approved: true },
    'student1': { password: 'sat_demo', accessType: 'trial', approved: true },
    'preview': { password: 'tryout', accessType: 'trial', approved: true },
    
    // Premium users (unlimited access)
    'premium1': { password: 'fullaccess2024', accessType: 'unlimited', approved: true },
    'vip_user': { password: 'unlimited_sat', accessType: 'unlimited', approved: true },
    'client_alpha': { password: 'premium_key_2024', accessType: 'unlimited', approved: true },
    'student_pro': { password: 'sat_unlimited', accessType: 'unlimited', approved: true },
    
    // Admin users (unlimited + admin privileges)
    'admin': { password: 'admin_secure_2024', accessType: 'admin', approved: true },
    'sathelper_admin': { password: 'master_control_2024', accessType: 'admin', approved: true },
    'owner': { password: 'creator_access_2024', accessType: 'admin', approved: true }
};

// Device restrictions
const DEVICE_RESTRICTIONS = {
    MAX_TRIAL_DEVICES: 3, // Allow up to 3 devices for trial accounts
    BLOCKED_IPS: [],
    BLOCKED_MACS: []
};

// In-memory storage for device tracking (in production, use a database)
let deviceRegistry = {};
let loginHistory = [];

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function logSecurityEvent(event, details) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        event,
        details
    };
    
    loginHistory.push(logEntry);
    
    // Keep only last 1000 entries
    if (loginHistory.length > 1000) {
        loginHistory = loginHistory.slice(-1000);
    }
    
    console.log(`[${logEntry.timestamp}] ${event}: ${details}`);
}

function generateApiKey() {
    return 'ak_' + crypto.randomBytes(32).toString('base64url');
}

function validateTrialDeviceLimit(username, accessType, deviceInfo) {
    if (accessType !== 'trial') {
        return { allowed: true };
    }
    
    // Count trial devices (excluding admin devices)
    const trialDevices = Object.values(deviceRegistry).filter(device => 
        device.users.some(user => USERS[user] && USERS[user].accessType === 'trial')
    );
    
    // Check if current device is already registered
    const currentDevice = deviceRegistry[deviceInfo.fingerprint];
    if (currentDevice) {
        return { allowed: true, reason: 'Device already registered' };
    }
    
    if (trialDevices.length >= DEVICE_RESTRICTIONS.MAX_TRIAL_DEVICES) {
        return {
            allowed: false,
            reason: `Trial account limit reached. Maximum ${DEVICE_RESTRICTIONS.MAX_TRIAL_DEVICES} devices allowed.`
        };
    }
    
    return { allowed: true };
}

function registerDeviceSession(username, accessType, deviceInfo) {
    const deviceId = deviceInfo.fingerprint;
    
    // Register device if not already registered
    if (!deviceRegistry[deviceId]) {
        deviceRegistry[deviceId] = {
            firstSeen: new Date().toISOString(),
            deviceInfo: {
                hostname: deviceInfo.hostname,
                platform: deviceInfo.platform,
                macAddresses: deviceInfo.macAddresses
            },
            users: []
        };
    }
    
    // Add user to device if not already associated
    if (!deviceRegistry[deviceId].users.includes(username)) {
        deviceRegistry[deviceId].users.push(username);
    }
    
    deviceRegistry[deviceId].lastSeen = new Date().toISOString();
    deviceRegistry[deviceId].lastUser = username;
    
    logSecurityEvent('DEVICE_REGISTERED', `User: ${username}, Device: ${deviceId.substring(0, 16)}...`);
}

export default async function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    try {
        const { username, password, deviceInfo } = req.body;
        
        if (!username || !password || !deviceInfo) {
            logSecurityEvent('AUTH_FAILED', 'Missing credentials or device info');
            return res.status(400).json({ 
                success: false, 
                message: 'Missing username, password, or device information' 
            });
        }
        
        // Check if user exists
        const user = USERS[username];
        if (!user) {
            logSecurityEvent('AUTH_FAILED', `User not found: ${username}`);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }
        
        // Check password
        if (user.password !== password) {
            logSecurityEvent('AUTH_FAILED', `Invalid password for: ${username}`);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }
        
        // Check if user is approved
        if (!user.approved) {
            logSecurityEvent('AUTH_FAILED', `User not approved: ${username}`);
            return res.status(403).json({ 
                success: false, 
                message: 'User account not approved' 
            });
        }
        
        // Check device restrictions for trial users
        const deviceValidation = validateTrialDeviceLimit(username, user.accessType, deviceInfo);
        if (!deviceValidation.allowed) {
            logSecurityEvent('AUTH_FAILED', `Device restriction: ${username} - ${deviceValidation.reason}`);
            return res.status(403).json({ 
                success: false, 
                message: deviceValidation.reason 
            });
        }
        
        // Register device session
        registerDeviceSession(username, user.accessType, deviceInfo);
        
        // Generate API key for future use
        const apiKey = generateApiKey();
        
        logSecurityEvent('AUTH_SUCCESS', `Username: ${username}, Access: ${user.accessType}`);
        
        return res.status(200).json({
            success: true,
            message: 'Authentication successful',
            username: username,
            accessType: user.accessType,
            apiKey: apiKey,
            deviceId: deviceInfo.fingerprint.substring(0, 16) + '...'
        });
        
    } catch (error) {
        console.error('Authentication error:', error);
        logSecurityEvent('AUTH_ERROR', error.message);
        
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
}
