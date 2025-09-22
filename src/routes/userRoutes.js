const express = require('express');
const userController = require('../controllers/userController');
const { authenticate, authorize, requireOwnershipOrAdmin } = require('../middleware/auth');
const { body, param, query, validationResult } = require('express-validator');
const { User, AuditLog } = require('../models');
const logger = require('../utils/logger');

const router = express.Router();

// Validation middleware
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      code: 'VALIDATION_ERROR',
      details: errors.array()
    });
  }
  next();
};

// Validation rules
const getUsersValidation = [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('status').optional().isIn(['active', 'inactive', 'pending', 'suspended', 'blocked']).withMessage('Invalid status'),
  query('sortBy').optional().isIn(['createdAt', 'updatedAt', 'firstName', 'lastName', 'email', 'status']).withMessage('Invalid sort field'),
  query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('Sort order must be asc or desc')
];

const userIdValidation = [
  param('userId').isMongoId().withMessage('Valid user ID is required')
];

const updateUserValidation = [
  param('userId').isMongoId().withMessage('Valid user ID is required'),
  body('firstName').optional().trim().isLength({ min: 1, max: 50 }).withMessage('First name must be 1-50 characters'),
  body('lastName').optional().trim().isLength({ min: 1, max: 50 }).withMessage('Last name must be 1-50 characters'),
  body('email').optional().isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('username').optional().trim().isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Username must be 3-30 characters and contain only letters, numbers, and underscores'),
  body('profile.phone').optional().isMobilePhone().withMessage('Valid phone number is required'),
  body('profile.department').optional().trim().isLength({ max: 100 }).withMessage('Department cannot exceed 100 characters'),
  body('profile.jobTitle').optional().trim().isLength({ max: 100 }).withMessage('Job title cannot exceed 100 characters')
];

const statusUpdateValidation = [
  param('userId').isMongoId().withMessage('Valid user ID is required'),
  body('status').isIn(['active', 'inactive', 'suspended', 'blocked']).withMessage('Invalid status')
];

const assignRolesValidation = [
  param('userId').isMongoId().withMessage('Valid user ID is required'),
  body('roleIds').isArray({ min: 1 }).withMessage('Role IDs array is required'),
  body('roleIds.*').isMongoId().withMessage('All role IDs must be valid MongoDB ObjectIds')
];

// All routes require authentication
router.use(authenticate);

/**
 * @route   GET /api/users
 * @desc    Get all users with pagination, filtering, and sorting
 * @access  Private (requires user:read permission)
 * @query   page, limit, status, role, search, sortBy, sortOrder, includeDeleted
 */
router.get(
  '/',
  authorize('user:read'),
  getUsersValidation,
  validateRequest,
  userController.getAllUsers
);

/**
 * @route   GET /api/users/stats
 * @desc    Get user statistics
 * @access  Private (requires user:read permission)
 */
router.get(
  '/stats',
  authorize('user:read'),
  userController.getUserStats
);

/**
 * @route   GET /api/users/:userId
 * @desc    Get single user by ID
 * @access  Private (requires user:read permission or ownership)
 */
router.get(
  '/:userId',
  authorize('user:read'),
  userIdValidation,
  validateRequest,
  userController.getUserById
);

/**
 * @route   PUT /api/users/:userId
 * @desc    Update user information
 * @access  Private (requires user:update permission or ownership)
 */
router.put(
  '/:userId',
  authorize(['user:update', 'user:manage'], 'OR'),
  updateUserValidation,
  validateRequest,
  requireOwnershipOrAdmin('userId'),
  userController.updateUser
);

/**
 * @route   DELETE /api/users/:userId
 * @desc    Delete user (soft delete)
 * @access  Private (requires user:delete permission)
 */
router.delete(
  '/:userId',
  authorize('user:delete'),
  userIdValidation,
  validateRequest,
  userController.deleteUser
);

/**
 * @route   PATCH /api/users/:userId/status
 * @desc    Activate/Deactivate user account
 * @access  Private (requires user:update permission)
 */
router.patch(
  '/:userId/status',
  authorize('user:update'),
  statusUpdateValidation,
  validateRequest,
  userController.toggleUserStatus
);

/**
 * @route   POST /api/users/:userId/roles
 * @desc    Assign roles to user
 * @access  Private (requires role:assign permission)
 */
router.post(
  '/:userId/roles',
  authorize('role:assign'),
  assignRolesValidation,
  validateRequest,
  userController.assignRoles
);

/**
 * @route   DELETE /api/users/:userId/roles/:roleId
 * @desc    Remove specific role from user
 * @access  Private (requires role:assign permission)
 */
router.delete(
  '/:userId/roles/:roleId',
  authorize('role:assign'),
  [
    param('userId').isMongoId().withMessage('Valid user ID is required'),
    param('roleId').isMongoId().withMessage('Valid role ID is required')
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { userId, roleId } = req.params;

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Remove role from user
      const updatedRoles = user.roles.filter(role => role.toString() !== roleId);
      
      if (updatedRoles.length === user.roles.length) {
        return res.status(400).json({
          success: false,
          error: 'User does not have this role',
          code: 'ROLE_NOT_ASSIGNED'
        });
      }

      await User.findByIdAndUpdate(userId, {
        roles: updatedRoles,
        updatedBy: req.user.id
      });

      // Log activity
      await AuditLog.createEntry({
        action: 'role_removed',
        actorType: 'user',
        userId: req.user.id,
        actorDetails: {
          username: req.user.username,
          email: req.user.email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        },
        targetType: 'user',
        targetId: userId,
        targetDetails: {
          name: user.fullName,
          removedRole: roleId
        },
        resource: 'user_roles',
        status: 'success',
        category: 'user_management'
      });

      res.status(200).json({
        success: true,
        message: 'Role removed successfully',
        data: {
          userId,
          removedRoleId: roleId
        }
      });

    } catch (error) {
      logger.error('Remove role error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to remove role',
        code: 'REMOVE_ROLE_ERROR'
      });
    }
  }
);

/**
 * @route   GET /api/users/:userId/permissions
 * @desc    Get all permissions for a user (from assigned roles)
 * @access  Private (requires user:read permission)
 */
router.get(
  '/:userId/permissions',
  authorize('user:read'),
  userIdValidation,
  validateRequest,
  async (req, res) => {
    try {
      const { userId } = req.params;

      const user = await User.findById(userId)
        .populate({
          path: 'roles',
          populate: {
            path: 'permissions',
            select: 'name displayName description category riskLevel'
          }
        });

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Collect all unique permissions
      const permissionsMap = new Map();
      
      user.roles.forEach(role => {
        role.permissions.forEach(permission => {
          permissionsMap.set(permission._id.toString(), {
            id: permission._id,
            name: permission.name,
            displayName: permission.displayName,
            description: permission.description,
            category: permission.category,
            riskLevel: permission.riskLevel,
            grantedByRoles: permissionsMap.has(permission._id.toString())
              ? [...permissionsMap.get(permission._id.toString()).grantedByRoles, role.name]
              : [role.name]
          });
        });
      });

      const permissions = Array.from(permissionsMap.values());

      // Group by category
      const permissionsByCategory = permissions.reduce((acc, permission) => {
        const category = permission.category || 'uncategorized';
        if (!acc[category]) acc[category] = [];
        acc[category].push(permission);
        return acc;
      }, {});

      res.status(200).json({
        success: true,
        message: 'User permissions retrieved successfully',
        data: {
          userId,
          userName: user.fullName,
          totalPermissions: permissions.length,
          permissions,
          permissionsByCategory,
          roles: user.roles.map(role => ({
            id: role._id,
            name: role.name,
            displayName: role.displayName,
            level: role.level
          }))
        }
      });

    } catch (error) {
      logger.error('Get user permissions error:', error.message);
      
      res.status(500).json({
        success: false,
        error: 'Failed to retrieve user permissions',
        code: 'GET_PERMISSIONS_ERROR'
      });
    }
  }
);

module.exports = router;