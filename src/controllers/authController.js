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
  
}