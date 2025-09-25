const express = require('express');
const roleController = require('../controllers/roleController');
const { authenticate, authorize } = require('../middleware/auth');
const { body, param, query, validationResult } = require('express-validator');

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
const getRolesValidation = [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('status').optional().isIn(['active', 'inactive']).withMessage('Invalid status'),
  query('level').optional().isInt({ min: 1, max: 10 }).withMessage('Level must be between 1 and 10'),
  query('sortBy').optional().isIn(['level', 'createdAt', 'updatedAt', 'name', 'displayName']).withMessage('Invalid sort field'),
  query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('Sort order must be asc or desc')
];

const roleIdValidation = [
  param('roleId').isMongoId().withMessage('Valid role ID is required')
];

const createRoleValidation = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Role name must be 2-50 characters')
    .matches(/^[a-zA-Z0-9_\s-]+$/)
    .withMessage('Role name can only contain letters, numbers, spaces, underscores, and hyphens'),
  body('displayName')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Display name must be 2-100 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters'),
  body('level')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Level must be between 1 and 100'),
  body('permissions')
    .optional()
    .isArray()
    .withMessage('Permissions must be an array'),
  body('permissions.*')
    .optional()
    .isMongoId()
    .withMessage('All permission IDs must be valid MongoDB ObjectIds'),
  body('parentRole')
    .optional()
    .isMongoId()
    .withMessage('Parent role must be a valid MongoDB ObjectId'),
  body('color')
    .optional()
    .matches(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/)
    .withMessage('Color must be a valid hex color code'),
  body('maxUsers')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Max users must be a positive integer')
];

const updateRoleValidation = [
  param('roleId').isMongoId().withMessage('Valid role ID is required'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Role name must be 2-50 characters')
    .matches(/^[a-zA-Z0-9_\s-]+$/)
    .withMessage('Role name can only contain letters, numbers, spaces, underscores, and hyphens'),
  body('displayName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Display name must be 2-100 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters'),
  body('level')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Level must be between 1 and 100'),
  body('permissions')
    .optional()
    .isArray()
    .withMessage('Permissions must be an array'),
  body('permissions.*')
    .optional()
    .isMongoId()
    .withMessage('All permission IDs must be valid MongoDB ObjectIds'),
  body('parentRole')
    .optional()
    .isMongoId()
    .withMessage('Parent role must be a valid MongoDB ObjectId'),
  body('color')
    .optional()
    .matches(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/)
    .withMessage('Color must be a valid hex color code'),
  body('maxUsers')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Max users must be a positive integer'),
  body('status')
    .optional()
    .isIn(['active', 'inactive'])
    .withMessage('Status must be active or inactive')
];

// All routes require authentication
router.use(authenticate);

/**
 * @route   GET /api/roles
 * @desc    Get all roles with pagination, filtering, and sorting
 * @access  Private (requires role:read permission)
 * @query   page, limit, status, level, search, sortBy, sortOrder, includeDeleted
 */
router.get(
  '/',
  authorize('role:read'),
  getRolesValidation,
  validateRequest,
  roleController.getAllRoles
);

/**
 * @route   GET /api/roles/stats
 * @desc    Get role statistics and analytics
 * @access  Private (requires role:read permission)
 */
router.get(
  '/stats',
  authorize('role:read'),
  roleController.getRoleStats
);

/**
 * @route   GET /api/roles/hierarchy
 * @desc    Get role hierarchy tree structure
 * @access  Private (requires role:read permission)
 */
router.get(
  '/hierarchy',
  authorize('role:read'),
  roleController.getRoleHierarchy
);

/**
 * @route   GET /api/roles/:roleId
 * @desc    Get single role by ID with detailed information
 * @access  Private (requires role:read permission)
 */
router.get(
  '/:roleId',
  authorize('role:read'),
  roleIdValidation,
  validateRequest,
  roleController.getRoleById
);

/**
 * @route   POST /api/roles
 * @desc    Create a new role
 * @access  Private (requires role:create permission)
 */
router.post(
  '/',
  authorize('role:create'),
  createRoleValidation,
  validateRequest,
  roleController.createRole
);

/**
 * @route   PUT /api/roles/:roleId
 * @desc    Update existing role
 * @access  Private (requires role:update permission)
 */
router.put(
  '/:roleId',
  authorize('role:update'),
  updateRoleValidation,
  validateRequest,
  roleController.updateRole
);

/**
 * @route   DELETE /api/roles/:roleId
 * @desc    Delete role (soft delete)
 * @access  Private (requires role:delete permission)
 */
router.delete(
  '/:roleId',
  authorize('role:delete'),
  roleIdValidation,
  validateRequest,
  roleController.deleteRole
);

module.exports = router;