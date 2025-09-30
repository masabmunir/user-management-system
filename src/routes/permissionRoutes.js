const express = require('express');
const permissionController = require('../controllers/permissionController');
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
const getPermissionsValidation = [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 200 }).withMessage('Limit must be between 1 and 200'),
  query('category').optional().trim().isLength({ min: 1 }).withMessage('Category cannot be empty'),
  query('riskLevel').optional().isIn(['low', 'medium', 'high', 'critical']).withMessage('Invalid risk level'),
  query('sortBy').optional().isIn(['name', 'displayName', 'category', 'riskLevel', 'createdAt']).withMessage('Invalid sort field'),
  query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('Sort order must be asc or desc')
];

const permissionIdValidation = [
  param('permissionId').isMongoId().withMessage('Valid permission ID is required')
];

const createPermissionValidation = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Permission name must be 2-100 characters')
    .matches(/^[a-zA-Z0-9_:.-]+$/)
    .withMessage('Permission name can only contain letters, numbers, colons, underscores, periods, and hyphens'),
  body('displayName')
    .trim()
    .isLength({ min: 2, max: 150 })
    .withMessage('Display name must be 2-150 characters'),
  body('description')
    .trim()
    .isLength({ min: 5, max: 500 })
    .withMessage('Description must be 5-500 characters'),
  body('category')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Category must be 2-100 characters'),
  body('resource')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Resource cannot exceed 100 characters'),
  body('action')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Action cannot exceed 100 characters'),
  body('riskLevel')
    .optional()
    .isIn(['low', 'medium', 'high', 'critical'])
    .withMessage('Risk level must be low, medium, high, or critical')
];

const updatePermissionValidation = [
  param('permissionId').isMongoId().withMessage('Valid permission ID is required'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Permission name must be 2-100 characters')
    .matches(/^[a-zA-Z0-9_:.-]+$/)
    .withMessage('Permission name can only contain letters, numbers, colons, underscores, periods, and hyphens'),
  body('displayName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 150 })
    .withMessage('Display name must be 2-150 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ min: 5, max: 500 })
    .withMessage('Description must be 5-500 characters'),
  body('category')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Category must be 2-100 characters'),
  body('riskLevel')
    .optional()
    .isIn(['low', 'medium', 'high', 'critical'])
    .withMessage('Risk level must be low, medium, high, or critical')
];

// All routes require authentication
router.use(authenticate);

/**
 * @route   GET /api/permissions
 * @desc    Get all permissions with filtering and sorting
 * @access  Private (requires permission:read)
 * @query   page, limit, category, riskLevel, search, sortBy, sortOrder, includeDeleted
 */
router.get(
  '/',
  authorize('permission:read'),
  getPermissionsValidation,
  validateRequest,
  permissionController.getAllPermissions
);

/**
 * @route   GET /api/permissions/stats
 * @desc    Get permission statistics and analytics
 * @access  Private (requires permission:read)
 */
router.get(
  '/stats',
  authorize('permission:read'),
  permissionController.getPermissionStats
);

/**
 * @route   GET /api/permissions/categories
 * @desc    Get all permission categories with counts
 * @access  Private (requires permission:read)
 */
router.get(
  '/categories',
  authorize('permission:read'),
  permissionController.getPermissionCategories
);

/**
 * @route   GET /api/permissions/:permissionId
 * @desc    Get single permission by ID with usage info
 * @access  Private (requires permission:read)
 */
router.get(
  '/:permissionId',
  authorize('permission:read'),
  permissionIdValidation,
  validateRequest,
  permissionController.getPermissionById
);

/**
 * @route   POST /api/permissions
 * @desc    Create a new permission
 * @access  Private (requires permission:create)
 */
router.post(
  '/',
  authorize('permission:create'),
  createPermissionValidation,
  validateRequest,
  permissionController.createPermission
);

/**
 * @route   PUT /api/permissions/:permissionId
 * @desc    Update existing permission
 * @access  Private (requires permission:update)
 */
router.put(
  '/:permissionId',
  authorize('permission:update'),
  updatePermissionValidation,
  validateRequest,
  permissionController.updatePermission
);

/**
 * @route   DELETE /api/permissions/:permissionId
 * @desc    Delete permission (soft delete)
 * @access  Private (requires permission:delete)
 */
router.delete(
  '/:permissionId',
  authorize('permission:delete'),
  permissionIdValidation,
  validateRequest,
  permissionController.deletePermission
);

module.exports = router;