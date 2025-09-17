require('dotenv').config();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const logger = require('./logger');

class JWTService {
  constructor() {
    this.accessTokenSecret = process.env.JWT_ACCESS_SECRET;
    this.refreshTokenSecret = process.env.JWT_REFRESH_SECRET;
    this.accessTokenExpiry = process.env.JWT_ACCESS_EXPIRY || '15m';
    this.refreshTokenExpiry = process.env.JWT_REFRESH_EXPIRY || '7d';
    
    if (!this.accessTokenSecret || !this.refreshTokenSecret) {
      throw new Error('JWT secrets are required in environment variables');
    }
  }

  /**
   * Generate access token for user
   * @param {Object} payload - User payload
   * @returns {string} JWT access token
   */
  generateAccessToken(payload) {
    try {
      const tokenPayload = {
        userId: payload.userId,
        email: payload.email,
        username: payload.username,
        roles: payload.roles.map(role => role._id || role), // Just IDs, not full objects
        permissions: payload.permissions,
        sessionId: payload.sessionId || this.generateSessionId(),
        type: 'access'
      };

      return jwt.sign(tokenPayload, this.accessTokenSecret, {
        expiresIn: this.accessTokenExpiry,
        issuer: 'user-management-system',
        audience: 'user-management-client'
      });
    } catch (error) {
      logger.error('Error generating access token:', error.message);
      throw new Error('Token generation failed');
    }
  }

  /**
   * Generate refresh token for user
   * @param {Object} payload - User payload
   * @returns {string} JWT refresh token
   */
  generateRefreshToken(payload) {
    try {
      const tokenPayload = {
        userId: payload.userId,
        email: payload.email,
        sessionId: payload.sessionId || this.generateSessionId(),
        type: 'refresh'
      };

      return jwt.sign(tokenPayload, this.refreshTokenSecret, {
        expiresIn: this.refreshTokenExpiry,
        issuer: 'user-management-system',
        audience: 'user-management-client'
      });
    } catch (error) {
      logger.error('Error generating refresh token:', error.message);
      throw new Error('Refresh token generation failed');
    }
  }

  /**
   * Generate both access and refresh tokens
   * @param {Object} user - User object
   * @returns {Object} Token pair
   */
  generateTokenPair(user) {
    const sessionId = this.generateSessionId();
    
    const payload = {
      userId: user._id,
      email: user.email,
      username: user.username,
      roles: user.roles,
      permissions: user.permissions || [],
      sessionId
    };

    return {
      accessToken: this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken(payload),
      sessionId,
      expiresIn: this.parseExpiry(this.accessTokenExpiry),
      tokenType: 'Bearer'
    };
  }

  /**
   * Verify access token
   * @param {string} token - JWT access token
   * @returns {Object} Decoded payload
   */
  verifyAccessToken(token) {
    try {
      return jwt.verify(token, this.accessTokenSecret, {
        issuer: 'user-management-system',
        audience: 'user-management-client'
      });
    } catch (error) {
      logger.error('Access token verification failed:', error.message);
      
      if (error.name === 'TokenExpiredError') {
        throw new Error('Access token expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid access token');
      } else {
        throw new Error('Access token verification failed');
      }
    }
  }

  /**
   * Verify refresh token
   * @param {string} token - JWT refresh token
   * @returns {Object} Decoded payload
   */
  verifyRefreshToken(token) {
    try {
      return jwt.verify(token, this.refreshTokenSecret, {
        issuer: 'user-management-system',
        audience: 'user-management-client'
      });
    } catch (error) {
      logger.error('Refresh token verification failed:', error.message);
      
      if (error.name === 'TokenExpiredError') {
        throw new Error('Refresh token expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid refresh token');
      } else {
        throw new Error('Refresh token verification failed');
      }
    }
  }

  /**
   * Decode token without verification (for debugging)
   * @param {string} token - JWT token
   * @returns {Object} Decoded payload
   */
  decodeToken(token) {
    try {
      return jwt.decode(token, { complete: true });
    } catch (error) {
      logger.error('Token decode failed:', error.message);
      return null;
    }
  }

  /**
   * Generate unique session ID
   * @returns {string} Session ID
   */
  generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Get token from Authorization header
   * @param {string} authHeader - Authorization header value
   * @returns {string|null} Extracted token
   */
  extractTokenFromHeader(authHeader) {
    if (!authHeader) return null;
    
    const parts = authHeader.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      return parts[1];
    }
    
    return null;
  }

  /**
   * Check if token is expired
   * @param {Object} decodedToken - Decoded JWT payload
   * @returns {boolean} True if expired
   */
  isTokenExpired(decodedToken) {
    if (!decodedToken.exp) return true;
    
    const currentTime = Math.floor(Date.now() / 1000);
    return decodedToken.exp < currentTime;
  }

  /**
   * Get token expiry time in seconds
   * @param {Object} decodedToken - Decoded JWT payload
   * @returns {number} Expiry timestamp
   */
  getTokenExpiry(decodedToken) {
    return decodedToken.exp || 0;
  }

  /**
   * Get time until token expires
   * @param {Object} decodedToken - Decoded JWT payload
   * @returns {number} Seconds until expiry
   */
  getTimeToExpiry(decodedToken) {
    const currentTime = Math.floor(Date.now() / 1000);
    const expiry = this.getTokenExpiry(decodedToken);
    return Math.max(0, expiry - currentTime);
  }

  /**
   * Parse expiry string to seconds
   * @param {string} expiry - Expiry string (e.g., '15m', '7d')
   * @returns {number} Seconds
   */
  parseExpiry(expiry) {
    const units = {
      's': 1,
      'm': 60,
      'h': 3600,
      'd': 86400
    };
    
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) return 900; // Default 15 minutes
    
    const [, value, unit] = match;
    return parseInt(value) * (units[unit] || 60);
  }

  /**
   * Create password reset token
   * @param {string} userId - User ID
   * @returns {string} Reset token
   */
  generatePasswordResetToken(userId) {
    try {
      return jwt.sign(
        { 
          userId, 
          type: 'password_reset',
          timestamp: Date.now()
        },
        this.accessTokenSecret,
        { expiresIn: '1h' } // Password reset expires in 1 hour
      );
    } catch (error) {
      logger.error('Error generating password reset token:', error.message);
      throw new Error('Reset token generation failed');
    }
  }

  /**
   * Create email verification token
   * @param {string} userId - User ID
   * @param {string} email - User email
   * @returns {string} Verification token
   */
  generateEmailVerificationToken(userId, email) {
    try {
      return jwt.sign(
        { 
          userId, 
          email,
          type: 'email_verification',
          timestamp: Date.now()
        },
        this.accessTokenSecret,
        { expiresIn: '24h' } // Email verification expires in 24 hours
      );
    } catch (error) {
      logger.error('Error generating email verification token:', error.message);
      throw new Error('Verification token generation failed');
    }
  }

  /**
   * Verify special tokens (password reset, email verification)
   * @param {string} token - Special token
   * @param {string} expectedType - Expected token type
   * @returns {Object} Decoded payload
   */
  verifySpecialToken(token, expectedType) {
    try {
      const decoded = jwt.verify(token, this.accessTokenSecret);
      
      if (decoded.type !== expectedType) {
        throw new Error(`Invalid token type. Expected: ${expectedType}`);
      }
      
      return decoded;
    } catch (error) {
      logger.error(`${expectedType} token verification failed:`, error.message);
      throw error;
    }
  }

  /**
   * Blacklist a token (store token ID for blacklist checking)
   * @param {string} token - JWT token
   * @returns {Object} Blacklist info
   */
  getTokenBlacklistInfo(token) {
    try {
      const decoded = this.decodeToken(token);
      if (!decoded) return null;
      
      return {
        jti: decoded.payload.jti || decoded.payload.sessionId,
        exp: decoded.payload.exp,
        userId: decoded.payload.userId
      };
    } catch (error) {
      logger.error('Error getting token blacklist info:', error.message);
      return null;
    }
  }
}

// Create and export singleton instance
const jwtService = new JWTService();

module.exports = jwtService;