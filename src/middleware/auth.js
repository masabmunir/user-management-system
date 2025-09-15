const jwtService = require('../utils/jwt');
const { User } = require('../models');
const logger = require('../utils/logger');

/**
 * Authentication middleware to verify JWT tokens
 */
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = jwtService.extractTokenFromHeader(authHeader);

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access token required',
        code: 'TOKEN_REQUIRED'
      });
    }

    // Verify the access token
    const decoded = jwtService.verifyAccessToken(token);
    
    // Check if token type is correct
    if (decoded.type !== 'access') {
      return res.status(401).json({
        success: false,
        error: 'Invalid token type',
        code: 'INVALID_TOKEN_TYPE'
      });
    }

    // Get user from database to ensure they still exist and are active
    const user = await User.findById(decoded.userId)
      .populate('roles')
      .select('+password'); // Include password for password change checks

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // Check if user is active
    if (user.status !== 'active') {
      return res.status(401).json({
        success: false,
        error: 'Account is not active',
        code: 'ACCOUNT_INACTIVE'
      });
    }

    // Check if user is locked
    if (user.isLocked) {
      return res.status(423).json({
        success: false,
        error: 'Account is temporarily locked',
        code: 'ACCOUNT_LOCKED'
      });
    }

    // Check if password was changed after token was issued
    if (user.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({
        success: false,
        error: 'Password was recently changed. Please login again',
        code: 'PASSWORD_CHANGED'
      });
    }

    // Populate permissions from roles
    await user.populate({
      path: 'roles',
      populate: {
        path: 'permissions'
      }
    });

    // Collect all permissions from all roles
    const permissions = new Set();
    user.roles.forEach(role => {
      role.permissions.forEach(permission => {
        permissions.add(permission.name);
      });
    });

    // Add user info to request object
    req.user = {
      id: user._id,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      fullName: user.fullName,
      roles: user.roles.map(role => ({
        id: role._id,
        name: role.name,
        displayName: role.displayName,
        level: role.level
      })),
      permissions: Array.from(permissions),
      sessionId: decoded.sessionId,
      status: user.status,
      emailVerified: user.emailVerified,
      twoFactorEnabled: user.twoFactorEnabled
    };

    // Add token info
    req.tokenInfo = {
      accessToken: token,
      sessionId: decoded.sessionId,
      issuedAt: new Date(decoded.iat * 1000),
      expiresAt: new Date(decoded.exp * 1000)
    };

    logger.info(`User authenticated: ${user.email}`);
    next();

  } catch (error) {
    logger.error('Authentication error:', error.message);

    // Handle specific JWT errors
    if (error.message.includes('expired')) {
      return res.status(401).json({
        success: false,
        error: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }

    if (error.message.includes('invalid') || error.message.includes('malformed')) {
      return res.status(401).json({
        success: false,
        error: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }

    return res.status(401).json({
      success: false,
      error: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
};

/**
 * Authorization middleware to check user permissions
 * @param {string|Array} requiredPermissions - Required permission(s)
 * @param {string} logic - 'AND' or 'OR' for multiple permissions
 */
const authorize = (requiredPermissions, logic = 'AND') => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required',
          code: 'AUTH_REQUIRED'
        });
      }

      const userPermissions = req.user.permissions || [];
      const permissions = Array.isArray(requiredPermissions) 
        ? requiredPermissions 
        : [requiredPermissions];

      let hasPermission = false;

      if (logic === 'OR') {
        // User needs at least one of the required permissions
        hasPermission = permissions.some(permission => 
          userPermissions.includes(permission)
        );
      } else {
        // User needs all required permissions (AND logic)
        hasPermission = permissions.every(permission => 
          userPermissions.includes(permission)
        );
      }

      if (!hasPermission) {
        logger.warn(`Authorization failed for user ${req.user.email}. Required: ${permissions.join(', ')}, Has: ${userPermissions.join(', ')}`);
        
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions',
          code: 'INSUFFICIENT_PERMISSIONS',
          required: permissions,
          current: userPermissions
        });
      }

      logger.info(`Authorization successful for user ${req.user.email} with permissions: ${permissions.join(', ')}`);
      next();

    } catch (error) {
      logger.error('Authorization error:', error.message);
      return res.status(500).json({
        success: false,
        error: 'Authorization check failed',
        code: 'AUTHORIZATION_ERROR'
      });
    }
  };
};

/**
 * Role-based authorization middleware
 * @param {string|Array} requiredRoles - Required role(s)
 * @param {string} logic - 'AND' or 'OR' for multiple roles
 */
const authorizeRole = (requiredRoles, logic = 'OR') => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required',
          code: 'AUTH_REQUIRED'
        });
      }

      const userRoles = req.user.roles.map(role => role.name) || [];
      const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

      let hasRole = false;

      if (logic === 'OR') {
        // User needs at least one of the required roles
        hasRole = roles.some(role => userRoles.includes(role));
      } else {
        // User needs all required roles (AND logic)
        hasRole = roles.every(role => userRoles.includes(role));
      }

      if (!hasRole) {
        logger.warn(`Role authorization failed for user ${req.user.email}. Required: ${roles.join(', ')}, Has: ${userRoles.join(', ')}`);
        
        return res.status(403).json({
          success: false,
          error: 'Insufficient role privileges',
          code: 'INSUFFICIENT_ROLE',
          required: roles,
          current: userRoles
        });
      }

      logger.info(`Role authorization successful for user ${req.user.email} with roles: ${roles.join(', ')}`);
      next();

    } catch (error) {
      logger.error('Role authorization error:', error.message);
      return res.status(500).json({
        success: false,
        error: 'Role authorization check failed',
        code: 'ROLE_AUTHORIZATION_ERROR'
      });
    }
  };
};

/**
 * Optional authentication middleware (doesn't fail if no token)
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = jwtService.extractTokenFromHeader(authHeader);

    if (!token) {
      req.user = null;
      return next();
    }

    // Try to authenticate but don't fail if it doesn't work
    await authenticate(req, res, (error) => {
      if (error) {
        req.user = null;
      }
      next();
    });

  } catch (error) {
    req.user = null;
    next();
  }
};

/**
 * Check if user owns the resource or has admin privileges
 * @param {string} resourceUserIdParam - Parameter name for resource user ID
 */
const requireOwnershipOrAdmin = (resourceUserIdParam = 'userId') => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required',
          code: 'AUTH_REQUIRED'
        });
      }

      const resourceUserId = req.params[resourceUserIdParam];
      const currentUserId = req.user.id.toString();
      
      // Allow if user owns the resource
      if (resourceUserId === currentUserId) {
        return next();
      }

      // Allow if user has admin permissions
      const hasAdminPermission = req.user.permissions.some(permission => 
        permission.includes('user:manage') || permission.includes('user:update')
      );

      if (hasAdminPermission) {
        return next();
      }

      return res.status(403).json({
        success: false,
        error: 'Access denied. You can only access your own resources.',
        code: 'ACCESS_DENIED'
      });

    } catch (error) {
      logger.error('Ownership check error:', error.message);
      return res.status(500).json({
        success: false,
        error: 'Authorization check failed',
        code: 'AUTHORIZATION_ERROR'
      });
    }
  };
};

/**
 * Rate limiting based on user role
 */
const roleBasedRateLimit = (limits) => {
  return (req, res, next) => {
    if (!req.user) {
      return next();
    }

    const userRole = req.user.roles[0]?.name || 'user';
    const limit = limits[userRole] || limits.default || 100;

    // Implementation depends on your rate limiting strategy
    // This is a placeholder for role-based rate limiting
    req.rateLimit = limit;
    next();
  };
};

/**
 * Middleware to log user activity for audit
 */
const logActivity = (action, resource) => {
  return (req, res, next) => {
    // Store activity info for later logging
    req.auditInfo = {
      action,
      resource,
      userId: req.user?.id,
      userEmail: req.user?.email,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date()
    };
    
    next();
  };
};

module.exports = {
  authenticate,
  authorize,
  authorizeRole,
  optionalAuth,
  requireOwnershipOrAdmin,
  roleBasedRateLimit,
  logActivity
};