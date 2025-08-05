// /api/admin-auth.js - Admin authentication endpoint with RSA verification
import crypto from 'crypto';

// Admin security configuration
const ADMIN_SECURITY = {
    // Authorized MAC addresses for admin access
    ALLOWED_MAC_ADDRESSES: ['88:66:5a:46:b0:d0'], // Replace with your actual MAC
    
    // RSA Public Key for signature verification
    ADMIN_RSA_PUBLIC_KEY: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Dojkpn9uLlpJGfMnKJ/
G8DNP0F4uq78lrbCnZvKWFQmf3Mj3LoRWZPga9MYmSvfIbLJmaL/PMslxbDyXvI7
CIGCwPtZVqeE6S6UJ/EeD0EpJCNetWUOPOZ/Vqo+WrY/TaXQix/IzFNKXMj0Ul43
shU/BWM5lnPoxGtu2g0Z3hmhqDeHFQKG23V68K7d1xHhJkmlCVkSgQs+Oe/rkAHL
4g7vd1ViJ33dF4wKiWLKTmvcYOJXbNPE/RXwvb48qtPWoy2R1E0Jg52KNEUG2hDx
wmWRcyAv2bALB5G0EANaYQCieOethyykt2lo7rV7fy6jtxE+HoiGE0kLAmlbsoHc
wQIDAQAB
-----END PUBLIC KEY-----`
};

// In-memory storage for admin sessions
let adminSessions = {};
let adminLoginHistory = [];

function logSecurityEvent(event, details) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        event,
        details
    };
    
    adminLoginHistory.push(logEntry);
    
    // Keep only last 500 admin entries
    if (adminLoginHistory.length > 500) {
        adminLoginHistory = adminLoginHistory.slice(-500);
    }
    
    console.log(`[ADMIN] [${logEntry.timestamp}] ${event}: ${details}`);
}

function validateMacAddress(deviceInfo) {
    const deviceMacs = deviceInfo.macAddresses || [];
    return ADMIN_SECURITY.ALLOWED_MAC_ADDRESSES.some(allowedMac => 
        deviceMacs.includes(allowedMac.toLowerCase())
    );
}

function verifyRSASignature(challenge, signature) {
    try {
        const publicKey = crypto.createPublicKey({
            key: ADMIN_SECURITY.ADMIN_RSA_PUBLIC_KEY,
            format: 'pem',
            type: 'spki'
        });
        
        return crypto.verify('sha256', Buffer.from(challenge), publicKey, Buffer.from(signature, 'base64'));
    } catch (error) {
        console.error('RSA verification error:', error);
        return false;
    }
}

function generateAdminToken() {
    return 'admin_' + crypto.randomBytes(32).toString('base64url');
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
        const { challenge, signature, deviceInfo } = req.body;
        
        if (!challenge || !signature || !deviceInfo) {
            logSecurityEvent('ADMIN_AUTH_FAILED', 'Missing challenge, signature, or device info');
            return res.status(400).json({ 
                success: false, 
                message: 'Missing challenge, signature, or device information' 
            });
        }
        
        // Step 1: Validate MAC address
        if (!validateMacAddress(deviceInfo)) {
            logSecurityEvent('ADMIN_AUTH_FAILED', `Unauthorized MAC: ${deviceInfo.macAddresses?.join(', ')}`);
            return res.status(403).json({ 
                success: false, 
                message: 'Unauthorized device - MAC address not allowed' 
            });
        }
        
        logSecurityEvent('ADMIN_MAC_VALIDATED', `Device: ${deviceInfo.hostname}`);
        
        // Step 2: Verify RSA signature
        if (!verifyRSASignature(challenge, signature)) {
            logSecurityEvent('ADMIN_AUTH_FAILED', 'Invalid RSA signature');
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid RSA signature' 
            });
        }
        
        logSecurityEvent('ADMIN_RSA_VALIDATED', 'RSA signature verified');
        
        // Generate admin session token
        const adminToken = generateAdminToken();
        const sessionId = crypto.randomBytes(16).toString('hex');
        
        // Store admin session
        adminSessions[sessionId] = {
            token: adminToken,
            deviceInfo: deviceInfo,
            loginTime: new Date().toISOString(),
            lastActivity: new Date().toISOString()
        };
        
        logSecurityEvent('ADMIN_ACCESS_GRANTED', `Session: ${sessionId}, Device: ${deviceInfo.fingerprint?.substring(0, 16)}...`);
        
        return res.status(200).json({
            success: true,
            message: 'Admin authentication successful',
            accessType: 'admin',
            adminToken: adminToken,
            sessionId: sessionId,
            privileges: [
                'user_management',
                'system_control',
                'security_logs',
                'device_management',
                'full_access'
            ]
        });
        
    } catch (error) {
        console.error('Admin authentication error:', error);
        logSecurityEvent('ADMIN_AUTH_ERROR', error.message);
        
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
}
