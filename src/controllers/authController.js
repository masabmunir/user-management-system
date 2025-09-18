const { User, Role, AuditLog } = require('../models');
const jwtService = require('../utils/jwt');
const logger = require('../utils/logger');
const crypto = require('crypto');

class AuthController {
  /**
   * Register a new user
   */
  async register(req, res) {
    try {
      const {
        firstName,
        lastName,
        email,
        username,
        password,
        confirmPassword
      } = req.body;

      // Validation
      if (!firstName || !lastName || !email || !username || !password) {
        return res.status(400).json({
          success: false,
          error: 'All fields are required',
          code: 'MISSING_FIELDS'
        });
      }

      if (password !== confirmPassword) {
        return res.status(400).json({
          success: false,
          error: 'Passwords do not match',
          code: 'PASSWORD_MISMATCH'
        });
      }

      // Check if user already exists
      const existingUser = await User.findOne({
        $or: [{ email }, { username }]
      });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          error: 'User with this email or username already exists',
          code: 'USER_EXISTS'
        });
      }

      // Get default role
      const defaultRole = await Role.findOne({ isDefault: true });
      if (!defaultRole) {
        throw new Error('Default role not found');
      }

      // Create user
      const user = new User({
        firstName,
        lastName,
        email,
        username,
        password, // Will be hashed automatically by pre-save middleware
        roles: [defaultRole._id],
        status: 'pending', // Requires email verification
        emailVerificationToken: crypto.randomBytes(32).toString('hex')
      });

      await user.save();

      // Log registration activity
      await AuditLog.createEntry({
        action: 'create',
        actorType: 'user',
        userId: user._id,
        actorDetails: {
          username: user.username,
          email: user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: user._id,
        targetDetails: {
          name: user.fullName,
          identifier: user.email
        },
        resource: 'user',
        status: 'success',
        category: 'user_management',
        endpoint: {
          method: req.method,
          path: req.path
        }
      });

      logger.info(`New user registered: ${email}`);

      res.status(201).json({
        success: true,
        message: 'User registered successfully. Please verify your email.',
        data: {
          user: {
            id: user._id,
            email: user.email,
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            status: user.status,
            emailVerified: user.emailVerified
          }
        }
      });

    } catch (error) {
      logger.error('Registration error:', error.message);

      // Handle duplicate key errors
      if (error.code === 11000) {
        const field = Object.keys(error.keyPattern)[0];
        return res.status(409).json({
          success: false,
          error: `${field} already exists`,
          code: 'DUPLICATE_FIELD'
        });
      }

      res.status(500).json({
        success: false,
        error: 'Registration failed',
        code: 'REGISTRATION_ERROR'
      });
    }
  }

  /**
   * User login
   */
/**
 * User login with detailed debugging
 */
async login(req, res) {
  try {
    const { email, password, remember = false } = req.body;

    if (!email || !password) {
      console.log('Missing credentials');
      return res.status(400).json({
        success: false,
        error: 'Email and password are required',
        code: 'MISSING_CREDENTIALS'
      });
    }

    // Find user and include password for verification
    const user = await User.findOne({ email })
      .select('+password')
      .populate({
        path: 'roles',
        populate: {
          path: 'permissions'
        }
      });

    if (!user) {
      console.log('User not found, logging failed attempt');
      await this.logFailedLogin(req, email, 'USER_NOT_FOUND');
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Check if account is locked
    if (user.isLocked) {
      console.log('Account is locked');
      await this.logFailedLogin(req, email, 'ACCOUNT_LOCKED');
      return res.status(423).json({
        success: false,
        error: 'Account is temporarily locked due to too many failed attempts',
        code: 'ACCOUNT_LOCKED',
        lockUntil: user.lockUntil
      });
    }

    // Check if account is active
    if (user.status !== 'active') {
      console.log('Account is not active, status:', user.status);
      await this.logFailedLogin(req, email, 'ACCOUNT_INACTIVE');
      return res.status(401).json({
        success: false,
        error: 'Account is not active',
        code: 'ACCOUNT_INACTIVE',
        status: user.status
      });
    }

    console.log('Step 4: About to verify password...');
    
    // Verify password
    const isPasswordValid = await user.correctPassword(password, user.password);
    
    if (!isPasswordValid) {
      console.log('Invalid password, incrementing login attempts');
      // Increment login attempts
      await user.incLoginAttempts();
      await this.logFailedLogin(req, email, 'INVALID_PASSWORD');
      
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    console.log('Step 6: Password valid, proceeding with login...');
    
    // Reset login attempts on successful login
    console.log('Step 6a: Resetting login attempts...');
    await user.resetLoginAttempts();
    console.log('Step 6b: Login attempts reset completed');

    console.log('Step 7: Processing user roles and permissions...');
    console.log('User roles count:', user.roles ? user.roles.length : 0);
    
    // Collect permissions from roles
    const permissions = new Set();
    if (user.roles && user.roles.length > 0) {
      user.roles.forEach((role, index) => {
        console.log(`Processing role ${index + 1}:`, role.name);
        if (role.permissions && role.permissions.length > 0) {
          role.permissions.forEach(permission => {
            permissions.add(permission.name);
          });
        }
      });
    }
    
    // Generate tokens
    const tokenPayload = {
      userId: user._id,
      email: user.email,
      username: user.username,
      roles: user.roles.map(role => role._id),
      permissions: Array.from(permissions)
    };
    
    console.log('Token payload prepared:', {
      userId: !!tokenPayload.userId,
      email: !!tokenPayload.email,
      username: !!tokenPayload.username,
      rolesCount: tokenPayload.roles.length,
      permissionsCount: tokenPayload.permissions.length
    });

    console.log('Step 10: Generating JWT tokens...');
    
    const tokens = jwtService.generateTokenPair({
      _id: user._id,
      email: user.email,
      username: user.username,
      roles: user.roles,
      permissions: Array.from(permissions)
    });

    console.log('Step 11: JWT tokens generated successfully');
    console.log('Access token exists:', !!tokens.accessToken);
    console.log('Refresh token exists:', !!tokens.refreshToken);
    console.log('Session ID:', tokens.sessionId);

    console.log('Step 12: Updating user login information...');
    
    // Update user login info
    await User.findByIdAndUpdate(user._id, {
      lastLogin: new Date(),
      lastLoginIP: req.ip,
      $push: {
        loginHistory: {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          loginTime: new Date(),
          success: true
        },
        activeSessions: {
          sessionId: tokens.sessionId,
          deviceInfo: req.get('User-Agent'),
          ip: req.ip,
          createdAt: new Date(),
          lastActivity: new Date()
        }
      }
    });

    console.log('Step 13: User login info updated successfully');
    console.log('Step 14: Creating audit log entry...');

    // Log successful login
    await AuditLog.createEntry({
      action: 'login',
      actorType: 'user',
      userId: user._id,
      actorDetails: {
        username: user.username,
        email: user.email,
        roles: user.roles.map(role => role.name),
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      },
      targetType: 'user',
      targetId: user._id,
      targetDetails: {
        name: user.fullName,
        identifier: user.email
      },
      resource: 'authentication',
      status: 'success',
      category: 'authentication',
      endpoint: {
        method: req.method,
        path: req.path
      },
      sessionId: tokens.sessionId
    });

    console.log('Step 15: Audit log created successfully');
    console.log('Step 16: Preparing response data...');

    // Prepare response
    const responseData = {
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: user.fullName,
        status: user.status,
        emailVerified: user.emailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
        roles: user.roles.map(role => ({
          id: role._id,
          name: role.name,
          displayName: role.displayName,
          level: role.level
        })),
        permissions: Array.from(permissions),
        lastLogin: user.lastLogin,
        profile: user.profile
      },
      tokens: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        tokenType: tokens.tokenType,
        expiresIn: tokens.expiresIn
      },
      sessionId: tokens.sessionId
    };

    console.log('Step 17: Response data prepared');
    
    // Set secure HTTP-only cookie for refresh token if remember is true
    if (remember) {
      console.log('Step 18a: Setting refresh token cookie...');
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });
      console.log('Step 18b: Refresh token cookie set');
    }

    console.log('Step 19: Sending successful response...');
    console.log('=== LOGIN COMPLETED SUCCESSFULLY ===');

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: responseData
    });

  } catch (error) {
    console.log('=== LOGIN ERROR OCCURRED ===');
    console.log('Error message:', error.message);
    console.log('Error stack:', error.stack);
    
    logger.error('Login error:', error.message);

    res.status(500).json({
      success: false,
      error: 'Login failed',
      code: 'LOGIN_ERROR'
    });
  }
}

  /**
   * Refresh access token using refresh token
   */
  async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body || req.cookies;

      if (!refreshToken) {
        return res.status(401).json({
          success: false,
          error: 'Refresh token required',
          code: 'REFRESH_TOKEN_REQUIRED'
        });
      }

      // Verify refresh token
      const decoded = jwtService.verifyRefreshToken(refreshToken);
      
      if (decoded.type !== 'refresh') {
        return res.status(401).json({
          success: false,
          error: 'Invalid token type',
          code: 'INVALID_TOKEN_TYPE'
        });
      }

      // Get user and validate
      const user = await User.findById(decoded.userId)
        .populate({
          path: 'roles',
          populate: {
            path: 'permissions'
          }
        });

      if (!user || user.status !== 'active') {
        return res.status(401).json({
          success: false,
          error: 'User not found or inactive',
          code: 'USER_INVALID'
        });
      }

      // Check if session exists
      const hasActiveSession = user.activeSessions.some(
        session => session.sessionId === decoded.sessionId
      );

      if (!hasActiveSession) {
        return res.status(401).json({
          success: false,
          error: 'Invalid session',
          code: 'INVALID_SESSION'
        });
      }

      // Collect permissions
      const permissions = new Set();
      user.roles.forEach(role => {
        role.permissions.forEach(permission => {
          permissions.add(permission.name);
        });
      });

      // Generate new access token
      const newAccessToken = jwtService.generateAccessToken({
        userId: user._id,
        email: user.email,
        username: user.username,
        roles: user.roles.map(role => role._id),
        permissions: Array.from(permissions),
        sessionId: decoded.sessionId
      });

      // Update session activity
      await User.findOneAndUpdate(
        { 
          _id: user._id, 
          'activeSessions.sessionId': decoded.sessionId 
        },
        { 
          $set: { 
            'activeSessions.$.lastActivity': new Date() 
          } 
        }
      );

      logger.info(`Token refreshed for user: ${user.email}`);

      res.status(200).json({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          accessToken: newAccessToken,
          tokenType: 'Bearer',
          expiresIn: jwtService.parseExpiry(process.env.JWT_ACCESS_EXPIRY || '15m')
        }
      });

    } catch (error) {
      logger.error('Token refresh error:', error.message);

      if (error.message.includes('expired') || error.message.includes('invalid')) {
        return res.status(401).json({
          success: false,
          error: 'Invalid or expired refresh token',
          code: 'INVALID_REFRESH_TOKEN'
        });
      }

      res.status(500).json({
        success: false,
        error: 'Token refresh failed',
        code: 'REFRESH_ERROR'
      });
    }
  }

  /**
   * User logout
   */
  async logout(req, res) {
    try {
      const { sessionId } = req.tokenInfo || {};
      const userId = req.user?.id;

      if (userId && sessionId) {
        // Remove session from user's active sessions
        await User.findByIdAndUpdate(userId, {
          $pull: {
            activeSessions: { sessionId }
          }
        });

        // Log logout activity
        await AuditLog.createEntry({
          action: 'logout',
          actorType: 'user',
          userId: userId,
          actorDetails: {
            username: req.user.username,
            email: req.user.email,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
          },
          targetType: 'user',
          targetId: userId,
          resource: 'authentication',
          status: 'success',
          category: 'authentication',
          sessionId: sessionId
        });
      }

      // Clear refresh token cookie
      res.clearCookie('refreshToken');

      logger.info(`User logged out: ${req.user?.email || 'unknown'}`);

      res.status(200).json({
        success: true,
        message: 'Logout successful'
      });

    } catch (error) {
      logger.error('Logout error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Logout failed',
        code: 'LOGOUT_ERROR'
      });
    }
  }

  /**
   * Logout from all sessions
   */
  async logoutAll(req, res) {
    try {
      const userId = req.user?.id;

      if (userId) {
        // Clear all active sessions
        await User.findByIdAndUpdate(userId, {
          $set: { activeSessions: [] }
        });

        // Log logout all activity
        await AuditLog.createEntry({
          action: 'logout',
          actorType: 'user',
          userId: userId,
          actorDetails: {
            username: req.user.username,
            email: req.user.email,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
          },
          targetType: 'user',
          targetId: userId,
          targetDetails: {
            action: 'logout_all_sessions'
          },
          resource: 'authentication',
          status: 'success',
          category: 'authentication'
        });
      }

      // Clear refresh token cookie
      res.clearCookie('refreshToken');

      logger.info(`User logged out from all sessions: ${req.user?.email || 'unknown'}`);

      res.status(200).json({
        success: true,
        message: 'Logged out from all sessions successfully'
      });

    } catch (error) {
      logger.error('Logout all error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Logout from all sessions failed',
        code: 'LOGOUT_ALL_ERROR'
      });
    }
  }

  /**
   * Get current user profile
   */
  async getProfile(req, res) {
    try {
      const user = await User.findById(req.user.id)
        .populate({
          path: 'roles',
          populate: {
            path: 'permissions'
          }
        });

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Collect permissions
      const permissions = new Set();
      user.roles.forEach(role => {
        role.permissions.forEach(permission => {
          permissions.add(permission.name);
        });
      });

      res.status(200).json({
        success: true,
        message: 'Profile retrieved successfully',
        data: {
          user: {
            id: user._id,
            email: user.email,
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            fullName: user.fullName,
            status: user.status,
            emailVerified: user.emailVerified,
            twoFactorEnabled: user.twoFactorEnabled,
            roles: user.roles.map(role => ({
              id: role._id,
              name: role.name,
              displayName: role.displayName,
              level: role.level,
              color: role.color,
              icon: role.icon
            })),
            permissions: Array.from(permissions),
            profile: user.profile,
            preferences: user.preferences,
            lastLogin: user.lastLogin,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
          }
        }
      });

    } catch (error) {
      logger.error('Get profile error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve profile',
        code: 'PROFILE_ERROR'
      });
    }
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(req, res) {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          error: 'Email is required',
          code: 'EMAIL_REQUIRED'
        });
      }

      const user = await User.findOne({ email });

      if (!user) {
        // Don't reveal that user doesn't exist
        return res.status(200).json({
          success: true,
          message: 'If the email exists, a password reset link has been sent.'
        });
      }

      // Generate password reset token
      const resetToken = user.createPasswordResetToken();
      await user.save();

      // Log password reset request
      await AuditLog.createEntry({
        action: 'password_reset',
        actorType: 'user',
        userId: user._id,
        actorDetails: {
          email: user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: user._id,
        resource: 'authentication',
        status: 'success',
        category: 'security'
      });

      // TODO: Send reset email (implement email service)
      logger.info(`Password reset requested for: ${email}, token: ${resetToken}`);

      res.status(200).json({
        success: true,
        message: 'If the email exists, a password reset link has been sent.',
        // Remove this in production - for testing only
        ...(process.env.NODE_ENV === 'development' && { resetToken })
      });

    } catch (error) {
      logger.error('Password reset request error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Password reset request failed',
        code: 'RESET_REQUEST_ERROR'
      });
    }
  }

  /**
   * Reset password with token
   */
  async resetPassword(req, res) {
    try {
      const { token, password, confirmPassword } = req.body;

      if (!token || !password || !confirmPassword) {
        return res.status(400).json({
          success: false,
          error: 'Token, password, and confirmation are required',
          code: 'MISSING_FIELDS'
        });
      }

      if (password !== confirmPassword) {
        return res.status(400).json({
          success: false,
          error: 'Passwords do not match',
          code: 'PASSWORD_MISMATCH'
        });
      }

      // Hash the token and find user
      const hashedToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');

      const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() }
      });

      if (!user) {
        return res.status(400).json({
          success: false,
          error: 'Invalid or expired reset token',
          code: 'INVALID_TOKEN'
        });
      }

      // Update password
      user.password = password;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      user.passwordChangedAt = new Date();

      // Clear all active sessions to force re-login
      user.activeSessions = [];

      await user.save();

      // Log password reset
      await AuditLog.createEntry({
        action: 'password_change',
        actorType: 'user',
        userId: user._id,
        actorDetails: {
          email: user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: user._id,
        resource: 'authentication',
        status: 'success',
        category: 'security'
      });

      logger.info(`Password reset completed for: ${user.email}`);

      res.status(200).json({
        success: true,
        message: 'Password reset successfully. Please login with your new password.'
      });

    } catch (error) {
      logger.error('Password reset error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Password reset failed',
        code: 'RESET_ERROR'
      });
    }
  }

  /**
   * Change password (authenticated user)
   */
 async changePassword(req, res) {
  try {
    console.log('=== CHANGE PASSWORD STARTED ===');
    console.log('Request body:', req.body);
    console.log('User ID from token:', req.user?.id);
    
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({
        success: false,
        error: 'All password fields are required',
        code: 'MISSING_FIELDS'
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        error: 'New passwords do not match',
        code: 'PASSWORD_MISMATCH'
      });
    }

    console.log('Step 1: About to find user...');
    // Get user with password
    const user = await User.findById(req.user.id).select('+password');
    console.log('Step 2: User found:', !!user);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    console.log('Step 3: About to verify current password...');
    // Verify current password
    const isCurrentPasswordValid = await user.correctPassword(
      currentPassword, 
      user.password
    );
    console.log('Step 4: Current password valid:', isCurrentPasswordValid);

    if (!isCurrentPasswordValid) {
      return res.status(400).json({
        success: false,
        error: 'Current password is incorrect',
        code: 'INVALID_CURRENT_PASSWORD'
      });
    }

    console.log('Step 5: About to update password...');
    // Update password
    user.password = newPassword;
    user.passwordChangedAt = new Date();
    
    console.log('Step 6: About to handle sessions...');
    console.log('User activeSessions exists:', !!user.activeSessions);
    console.log('Current sessionId:', req.tokenInfo?.sessionId);
    
    // Handle activeSessions safely
    if (user.activeSessions && Array.isArray(user.activeSessions)) {
      user.activeSessions = user.activeSessions.filter(
        session => session.sessionId === req.tokenInfo?.sessionId
      );
    } else {
      // If activeSessions doesn't exist, initialize it
      user.activeSessions = [];
    }

    console.log('Step 7: About to save user...');
    await user.save();
    console.log('Step 8: User saved successfully');

    console.log('Step 9: About to create audit log...');
    // Log password change - wrap in try-catch to isolate audit log issues
    try {
      await AuditLog.createEntry({
        action: 'password_change',
        actorType: 'user',
        userId: user._id,
        actorDetails: {
          username: user.username,
          email: user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: user._id,
        resource: 'authentication',
        status: 'success',
        category: 'security',
        sessionId: req.tokenInfo?.sessionId
      });
      console.log('Step 10: Audit log created successfully');
    } catch (auditError) {
      console.log('Audit log error (non-critical):', auditError.message);
      // Continue execution even if audit log fails
    }

    logger.info(`Password changed for user: ${user.email}`);
    console.log('=== CHANGE PASSWORD COMPLETED ===');

    res.status(200).json({
      success: true,
      message: 'Password changed successfully'
    });

  } catch (error) {
    console.log('=== CHANGE PASSWORD ERROR ===');
    console.log('Error message:', error.message);
    console.log('Error stack:', error.stack);
    
    logger.error('Change password error:', error.message);
    
    res.status(500).json({
      success: false,
      error: 'Password change failed',
      code: 'CHANGE_PASSWORD_ERROR'
    });
  }
}

  /**
   * Log failed login attempts
   * @private
   */
  async logFailedLogin(req, email, reason) {
    try {
      await AuditLog.createEntry({
        action: 'login',
        actorType: 'user',
        actorDetails: {
          email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        resource: 'authentication',
        status: 'failure',
        category: 'authentication',
        errorCode: reason,
        endpoint: {
          method: req.method,
          path: req.path
        }
      });
    } catch (error) {
      logger.error('Failed to log failed login attempt:', error.message);
    }
  }
}

module.exports = new AuthController();